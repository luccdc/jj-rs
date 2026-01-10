use std::{fmt::Write, net::SocketAddr, path::PathBuf, str::FromStr};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use clap::Parser;
use eyre::Context;
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

    /// Path to store log entries to, if you don't trust your network
    #[arg(short, long)]
    log_file: Option<PathBuf>,
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
    if let Some(log_file) = args.log_file {
        match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log_file)
        {
            Err(e) => {
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer())
                    .with(
                        tracing_subscriber::filter::Targets::new()
                            .with_target("jj_rs", tracing::Level::INFO),
                    )
                    .init();

                tracing::warn!(
                    "Unable to open log file for logging requests; all requests will only be logged to stdout! Error: {e}"
                );
            }
            Ok(l) => {
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer())
                    .with(tracing_subscriber::fmt::layer().json().with_writer(l))
                    .with(
                        tracing_subscriber::filter::Targets::new()
                            .with_target("jj_rs", tracing::Level::INFO),
                    )
                    .init();

                tracing::info!("Logging file requests to {}", log_file.display());
            }
        }
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(
                tracing_subscriber::filter::Targets::new()
                    .with_target("jj_rs", tracing::Level::INFO),
            )
            .init();
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    let listener = TcpListener::bind(addr).await?;

    let mut path = std::env::current_dir()?;
    let root_server = args.root_directory.canonicalize()?;
    path.extend(&root_server);
    let path = path.canonicalize()?;

    tracing::info!("Serving HTTP on {addr} from {}", path.display());

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

type ServeResponse = eyre::Result<Response<BoxBody<Bytes, std::io::Error>>>;

fn not_found() -> ServeResponse {
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
) -> ServeResponse {
    let mut path = root_path.clone();
    let uri = req.uri();

    let uri = uri.path();
    path.push(&uri[1..]);

    let Ok(path) = path.canonicalize() else {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string(),
            "Canonicalization failed; file may not exist"
        );
        return not_found();
    };

    if !path.starts_with(&root_path) {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string(),
            path = format!("{}", path.display()),
            root_path = format!("{}", root_path.display()),
            "LFI attempted; consider blocking client"
        );
        return not_found();
    }

    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        tracing::warn!(
            client = client.to_string(),
            code = 404,
            uri = uri.to_string(),
            path = format!("{}", path.display()),
            "Failed to gather metadata"
        );
        return not_found();
    };

    match if metadata.is_dir() {
        respond_dir(&req, path, uri.to_string(), client.to_string()).await
    } else {
        let result = respond_file(path).await;
        tracing::info!(
            client = client.to_string(),
            code = 200,
            uri = &uri,
            "Responding with file download"
        );
        result
    } {
        Ok(r) => Ok(r),
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
    client_string: String,
) -> ServeResponse {
    let mime_zip = mime::Mime::from_str("application/zip")
        .context("could not parse static constant mime type")?;
    let mime_html = mime::TEXT_HTML;
    let mime_plain = mime::TEXT_PLAIN;

    let available = vec![mime_plain.clone(), mime_zip.clone(), mime_html.clone()];

    let accept = req
        .headers()
        .get("accept")
        .and_then(|s| s.to_str().ok())
        .unwrap_or("text/plain");

    let negotiated = if accept == "*/*" {
        Ok(mime_plain.clone())
    } else {
        accept
            .parse::<accept_header::Accept>()?
            .negotiate(&available)
    };

    let body = match negotiated {
        Ok(m) if m == mime_zip => {
            let result = respond_dir_zip(path);
            tracing::info!(
                client = client_string,
                code = 200,
                uri = &uri,
                "Responding with zip file download"
            );
            result
        }
        Ok(m) if m == mime_html => {
            let result = respond_dir_html(path, &uri).await?;
            tracing::info!(
                client = client_string,
                code = 200,
                uri = &uri,
                "Responding with HTML listing"
            );
            result
        }
        Ok(m) if m == mime_plain => {
            let result = respond_dir_text(path, &uri).await?;
            tracing::info!(
                client = client_string,
                code = 200,
                uri = &uri,
                "Responding with plaintext listing"
            );
            result
        }
        Ok(_) => unreachable!(),
        Err(s) => {
            return Ok(Response::builder().status(s.as_u16()).body(
                Full::new(Bytes::from("400"))
                    .map_err(std::io::Error::other)
                    .boxed(),
            )?);
        }
    };

    Ok(Response::builder().status(StatusCode::OK).body(body)?)
}

fn respond_dir_zip(path: PathBuf) -> BoxBody<Bytes, std::io::Error> {
    let (read, write) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        if let Err(e) = respond_dir_zip_inner(path, write).await {
            tracing::error!("Error responding with zip file: {e}");
        }
    });

    let read = ReaderStream::new(read);
    StreamBody::new(read.map_ok(Frame::data)).boxed()
}

async fn respond_dir_zip_inner<W: tokio::io::AsyncWrite + std::marker::Unpin>(
    path: PathBuf,
    writer: W,
) -> eyre::Result<()> {
    use tokio_util::compat::FuturesAsyncWriteCompatExt;

    let mut entries = async_walkdir::WalkDir::new(&path);
    let mut writer = async_zip::tokio::write::ZipFileWriter::with_tokio(writer);

    while let Some(entry) = entries.next().await {
        let Ok(entry) = entry else {
            continue;
        };

        let Ok(ty) = entry.file_type().await else {
            continue;
        };

        if ty.is_dir() {
            continue;
        }

        #[cfg(unix)]
        #[allow(clippy::cast_possible_truncation)]
        let perms = entry
            .metadata()
            .await
            .map(|p| p.permissions().mode() as u16)
            .unwrap_or(0o775);
        #[cfg(windows)]
        let perms = 0o775;

        let Ok(name) = entry
            .path()
            .strip_prefix(&path)
            .map(|s| s.to_string_lossy().to_string())
        else {
            continue;
        };

        let opts = async_zip::ZipEntryBuilder::new(name.into(), async_zip::Compression::Deflate)
            .unix_permissions(perms);

        let Ok(mut file) = tokio::fs::File::open(entry.path()).await else {
            tracing::warn!(
                path = format!("{}", entry.path().display()),
                "Skipping storing file in archive"
            );
            continue;
        };

        let Ok(entry_writer) = writer.write_entry_stream(opts).await else {
            tracing::warn!(
                path = format!("{}", entry.path().display()),
                "Skipping storing file in archive"
            );
            continue;
        };
        let mut writer_compat = entry_writer.compat_write();

        if let Err(e) = tokio::io::copy(&mut file, &mut writer_compat).await {
            tracing::error!("Failed to copy file; zip file is corrupted! {e}");
            break;
        }

        if let Err(e) = writer_compat.into_inner().close().await {
            tracing::error!("Failed to copy file; zip file is corrupted! {e}");
            break;
        }
    }

    writer.close().await?;

    Ok(())
}

async fn respond_dir_html(
    path: PathBuf,
    uri: &str,
) -> eyre::Result<BoxBody<Bytes, std::io::Error>> {
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

    let display = format!(
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
    );

    Ok(Full::new(Bytes::from(display))
        .map_err(std::io::Error::other)
        .boxed())
}

async fn respond_dir_text(
    path: PathBuf,
    uri: &str,
) -> eyre::Result<BoxBody<Bytes, std::io::Error>> {
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

    let display = string_entries
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
        .join("\n");

    Ok(Full::new(Bytes::from(display))
        .map_err(std::io::Error::other)
        .boxed())
}

async fn respond_file(path: PathBuf) -> ServeResponse {
    let file = tokio::fs::File::open(path).await?;
    let reader_stream = ReaderStream::new(file);

    let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
    let boxed_body = stream_body.boxed();

    let response = Response::builder().status(StatusCode::OK).body(boxed_body);

    Ok(response?)
}
