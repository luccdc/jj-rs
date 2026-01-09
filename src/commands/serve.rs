use std::{fmt::Write, net::SocketAddr, path::PathBuf};

use clap::Parser;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Bytes, Frame};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_stream::{StreamExt, wrappers::ReadDirStream};
use tokio_util::io::ReaderStream;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Serve files from a directory
#[derive(Parser, Debug, Clone)]
pub struct Serve {
    /// Port to listen on to serve files
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Directory to serve files from
    #[arg(short, long, default_value = ".")]
    root_directory: PathBuf,
}

impl super::Command for Serve {
    fn execute(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async { serve(self).await })?;

        Ok(())
    }
}

async fn serve(args: Serve) -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::Targets::new().with_target("jj_rs", tracing::Level::INFO))
        .init();

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    let listener = TcpListener::bind(addr).await?;

    let mut path = std::env::current_dir()?;
    let root_server = args.root_directory.canonicalize()?;
    path.extend(&root_server);
    let path = path.canonicalize()?;

    tracing::info!("Serving HTTP on {addr}");

    loop {
        let (stream, client) = listener.accept().await?;

        let io = TokioIo::new(stream);

        let path = path.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| respond(path.clone(), req, client)),
                )
                .await
            {
                eprintln!("Error serving connection: {err:?}");
            }
        });
    }
}

fn not_found() -> eyre::Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let body = Full::new(Bytes::from("404"))
        .map_err(std::io::Error::other)
        .boxed();

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body)?)
}

async fn respond(
    root_path: PathBuf,
    req: Request<hyper::body::Incoming>,
    client: SocketAddr,
) -> eyre::Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let mut path = root_path.clone();
    let uri = req.uri();

    let uri = uri.path();
    path.push(&uri[1..]);

    let Ok(path) = path.canonicalize() else {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string()
        );
        return not_found();
    };

    if !path.starts_with(root_path) {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string()
        );
        return not_found();
    }

    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string()
        );
        return not_found();
    };

    match if metadata.is_dir() {
        respond_dir(&req, path, uri.to_string()).await
    } else {
        respond_file(path).await
    } {
        Ok(r) => {
            tracing::info!(
                client = client.to_string(),
                code = 200,
                uri = uri.to_string()
            );
            Ok(r)
        }
        Err(e) => {
            tracing::error!(
                client = client.to_string(),
                code = 500,
                uri = uri.to_string(),
                "Could not respond to client: {e}"
            );

            let body = Full::new(Bytes::from("error"))
                .map_err(std::io::Error::other)
                .boxed();

            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body)?)
        }
    }
}

async fn respond_dir(
    req: &Request<hyper::body::Incoming>,
    path: PathBuf,
    uri: String,
) -> eyre::Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let entries = tokio::fs::read_dir(&path).await?;
    let entries = ReadDirStream::new(entries)
        .collect::<Result<Vec<_>, _>>()
        .await?;

    let mut string_entries = entries
        .iter()
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let mut path = path.clone();
            path.push(&name);

            (name, std::fs::metadata(path))
        })
        .collect::<Vec<_>>();

    string_entries.sort_by_key(|(n, m)| {
        let dir = m.as_ref().is_ok_and(std::fs::Metadata::is_dir);
        (!dir, n.clone())
    });

    let width = string_entries
        .iter()
        .map(|(s, _)| s.len())
        .max()
        .unwrap_or_default();

    let size_width = string_entries
        .iter()
        .map(|(_, m)| {
            m.as_ref()
                .map(|metadata| {
                    format!("{}", if metadata.is_dir() { 0 } else { metadata.len() }).len()
                })
                .unwrap_or(1)
        })
        .max()
        .unwrap_or(1);

    let body = if req
        .headers()
        .get("accept")
        .and_then(|s| s.to_str().ok())
        .is_some_and(|s| s.contains("text/html"))
    {
        format!(
            "<!DOCTYPE html>
<html><head><style>table {{ border-collapse: collapse; }} td, th {{ border: 1px solid black; padding: 5px; }}</style></head><body>
<table>
<tr><th></th><th>Size</th><th>Name</th></tr>
{}
{}
</body></html>",
            if uri == "/" {
                String::new()
            } else {
                format!(r#"<tr><td>d</td><td></td><td><a href="{uri}/..">..</a></td></tr>"#)
            },
            string_entries
                .iter()
                .fold(String::new(), |mut output, (name, m)| {
                    let (dir_spec, size) = m
                        .as_ref()
                        .map(|metadata| {
                            if metadata.is_dir() {
                                ('d', " ".to_string())
                            } else {
                                (' ', format!("{}", metadata.len()))
                            }
                        })
                        .unwrap_or((' ', "-".to_string()));

                    let download_url = if uri == "/" {
                        format!("/{name}")
                    } else {
                        format!("{uri}/{name}")
                    };

                    let _ = writeln!(output, r#"<tr><td>{dir_spec}</td><td>{size}</td><td><a href="{download_url}">{name}</a></td></tr>"#);
                    output
                })
        )
    } else {
        format!(
            "{}\n",
            string_entries
                .iter()
                .map(|(name, m)| {
                    let (dir_spec, size) = m
                        .as_ref()
                        .map(|metadata| {
                            if metadata.is_dir() {
                                ('d', " ".to_string())
                            } else {
                                (' ', format!("{}", metadata.len()))
                            }
                        })
                        .unwrap_or((' ', "-".to_string()));

                    if uri == "/" {
                        format!("{dir_spec} - {size:>size_width$} - {name:width$} - /{name}")
                    } else {
                        format!("{dir_spec} - {size:>size_width$} - {name:width$} - {uri}/{name}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    let body = Full::new(Bytes::from(body))
        .map_err(std::io::Error::other)
        .boxed();

    Ok(Response::builder().status(StatusCode::OK).body(body)?)
}

async fn respond_file(path: PathBuf) -> eyre::Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let file = tokio::fs::File::open(path).await?;
    let reader_stream = ReaderStream::new(file);

    let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
    let boxed_body = stream_body.boxed();

    let response = Response::builder().status(StatusCode::OK).body(boxed_body);

    Ok(response?)
}
