use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Frame},
    header::HeaderName,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
use tracing::{Instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Establish a web application firewall with modsecurity, logging violations and potentially blocking them
#[derive(Parser, Debug)]
pub struct Proxy {
    /// Server to connect to, e.g. `localhost:80`, `example.org`, `192.168.1.1:8080`
    url: hyper::Uri,

    /// Port to listen on
    #[arg(default_value = "9090")]
    listen_port: u16,

    /// IP address to bind to. Defaults to unspecified
    #[arg(long, short = 'b')]
    listen_address: Option<Ipv4Addr>,

    /// File to log jj data to
    #[arg(long, short, default_value = "/var/log/jj-proxy.ndjson")]
    log_file: PathBuf,

    /// File to log modsecurity data to
    #[arg(long, default_value = "/var/log/jj-proxy-modsec.ndjson")]
    modsec_log_file: PathBuf,

    /// Disable the use of modsecurity to watch traffic and scan for malicious activity
    #[arg(long, short)]
    disable_modsecurity: bool,

    /// Disable the bundled OWASP Common Rule Set
    #[arg(long)]
    disable_common_ruleset: bool,

    /// Block traffic that modsecurity catches and marks invalid
    #[arg(long, short)]
    ips_mode: bool,

    /// Extra rules in modsecurity format to load and match
    #[arg(long, short)]
    extra_rules: Option<PathBuf>,

    /// Max size to buffer incoming requests. Set to 0 to instead stream requests and not analyze request bodies. Size is in KiB
    #[arg(long, short, default_value = "64")]
    max_upload_body_size: usize,

    /// Max size to buffer response requests. Set to 0 to instead stream requests and not analyze response bodies. Size is in KiB
    #[arg(long, short = 'M', default_value = "2048")]
    max_download_body_size: usize,

    /// Override Host header, ignoring the client Host header in favor of the url provided
    #[arg(long, short)]
    override_host_header: bool,
}

impl super::Command for Proxy {
    fn execute(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async { proxy(self).await })
    }

    fn setup_tracing(&self) -> eyre::Result<()> {
        match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_file)
        {
            Err(e) => {
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer())
                    .with(
                        tracing_subscriber::EnvFilter::builder()
                            .with_default_directive("jj_rs=info".parse()?)
                            .from_env_lossy(),
                    )
                    .init();

                tracing::warn!(
                    "Unable to open log file for logging requests; all requests will only be logged to stdout! Error: {e}"
                );
            }
            Ok(l) => {
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer().json().with_writer(l))
                    .with(
                        tracing_subscriber::filter::Targets::new()
                            .with_target("jj_rs", tracing::Level::INFO),
                    )
                    .with(tracing_subscriber::fmt::layer())
                    .with(
                        tracing_subscriber::EnvFilter::builder()
                            .with_default_directive("jj_rs=info".parse()?)
                            .from_env_lossy(),
                    )
                    .init();

                tracing::info!("Logging file requests to {}", self.log_file.display());
            }
        }

        Ok(())
    }
}

async fn proxy(args: Proxy) -> eyre::Result<()> {
    let addr = SocketAddr::from((
        args.listen_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
        args.listen_port,
    ));

    let listener = TcpListener::bind(addr).await?;

    let modsec = args.disable_modsecurity.then(|| Arc::new(()));
    let Some(host) = args.url.host().map(str::to_string) else {
        tracing::error!("Cannot parse host from provided url!");
        return Ok(());
    };

    tracing::info!("Proxying HTTP from {addr} to {}", &args.url);

    let args = Arc::new(args);

    loop {
        let (stream, client) = listener.accept().await?;

        let io = TokioIo::new(stream);

        let modsec = modsec.clone();
        let url = args.url.clone();
        let host = host.to_string();
        let args = Arc::clone(&args);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        respond_with_logging(
                            Arc::clone(&args),
                            req,
                            url.clone(),
                            host.clone(),
                            client,
                            modsec.clone(),
                        )
                    }),
                )
                .await
            {
                tracing::error!("Error serving connection: {err}");
            }
        });
    }
}

type ServeResponse = eyre::Result<Response<BoxBody<Bytes, std::io::Error>>>;

fn err_response<S: Into<StatusCode>, B: Into<Bytes>>(status: S, error: B) -> ServeResponse {
    let body = Full::new(error.into())
        .map_err(std::io::Error::other)
        .boxed();

    Ok(Response::builder().status(status).body(body)?)
}

async fn respond_with_logging(
    args: Arc<Proxy>,
    req: Request<hyper::body::Incoming>,
    server: hyper::Uri,
    host: String,
    client: SocketAddr,
    modsec: Option<Arc<()>>,
) -> ServeResponse {
    let span = tracing::info_span!(
        "proxy-response",
        uri = format!("{}", req.uri()),
        client = format!("{client}")
    );

    respond_inner(args, req, server, host, client, modsec)
        .instrument(span)
        .await
}

async fn respond_inner(
    args: Arc<Proxy>,
    req: Request<hyper::body::Incoming>,
    server: hyper::Uri,
    host: String,
    client: SocketAddr,
    modsec: Option<Arc<()>>,
) -> ServeResponse {
    let server_addr = format!("{host}:{}", server.port_u16().unwrap_or(80));
    let upstream_stream = match TcpStream::connect(server_addr).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                code = 502,
                "Error establishing connection to upstream server: {e}"
            );

            return err_response(
                StatusCode::BAD_GATEWAY,
                "Could not connect to upstream gateway",
            );
        }
    };
    let upstream_io = TokioIo::new(upstream_stream);
    let (mut upstream_sender, conn) = match hyper::client::conn::http1::handshake(upstream_io).await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                code = 502,
                "Upstream gateway did not respond with valid HTTP: {e}"
            );

            return err_response(
                StatusCode::BAD_GATEWAY,
                "Upstream gateway did not respond with valid HTTP",
            );
        }
    };
    tokio::task::spawn({
        let span = Span::current();
        async move {
            if let Err(e) = conn.await {
                tracing::error!("Could not finish client request: {e}");
            }
        }
        .instrument(span)
    });

    let (upstream_body_reader, mut upstream_body_writer) = tokio::io::duplex(65536);

    // modsecurity check request path
    let mut upstream_req = Request::builder().uri(req.uri());
    // modsecurity check headers
    for header in req.headers() {
        if args.override_host_header && header.0 == HeaderName::from_static("host") {
            continue;
        }
        upstream_req = upstream_req.header(header.0, header.1);
    }
    let upstream_req = if args.override_host_header
        && let Some(host) = server.host()
    {
        upstream_req.header("Host", host)
    } else {
        upstream_req
    };

    let upstream_req = match upstream_req
        .body(StreamBody::new(ReaderStream::new(upstream_body_reader).map_ok(Frame::data)).boxed())
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(code = 500, "Could not form request to upstream server: {e}");

            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not form request to upstream server; this is an error with the proxy",
            );
        }
    };

    let mut res =
        tokio::task::spawn(async move { upstream_sender.send_request(upstream_req).await });

    let mut body_buffer = Vec::new();

    let mut req_body = req.into_body();
    if args.max_upload_body_size == 0 {
        while let Some(next) = req_body.frame().await {
            let frame = match next {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(code = 400, "Could not read packet from client: {e}");

                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "Could not read packet from client",
                    );
                }
            };

            if let Some(chunk) = frame.data_ref() {
                if let Err(e) = upstream_body_writer.write_all(chunk).await {
                    tracing::error!(
                        code = 502,
                        "Could not forward body to upstream gateway: {e}"
                    );

                    return err_response(
                        StatusCode::BAD_GATEWAY,
                        "Could not forward body to upstream gateway",
                    );
                }
            }
        }
    } else {
        while let Some(next) = req_body.frame().await {
            let frame = match next {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(code = 400, "Could not read packet from client: {e}");

                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "Could not read packet from client",
                    );
                }
            };

            if let Some(chunk) = frame.data_ref() {
                body_buffer.extend_from_slice(chunk);

                if body_buffer.len() > args.max_upload_body_size * 1024 {
                    tracing::error!(
                        code = 413,
                        "Client request body exceeds configured maximum, exiting ({} > {})",
                        body_buffer.len(),
                        args.max_upload_body_size
                    );

                    return err_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request payload is too large",
                    );
                }
            }
        }

        // modsecurity check body

        if let Err(e) = upstream_body_writer.write_all(&body_buffer).await {
            tracing::error!(
                code = 502,
                "Could not forward body to upstream gateway: {e}"
            );

            return err_response(
                StatusCode::BAD_GATEWAY,
                "Could not forward body to upstream gateway",
            );
        }
    }

    let res = match res.await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::error!(code = 502, "Error sending request to upstream gateway: {e}");
            return err_response(
                StatusCode::BAD_GATEWAY,
                "Error sending request to upstream gateway",
            );
        }
        Err(_) => {
            tracing::error!(
                code = 500,
                "Panicked while waiting for response from upstream gateway"
            );
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to wait for response from upstream gateway",
            );
        }
    };

    let mut full_response = Response::builder().status(res.status());
    for header in res.headers() {
        full_response = full_response.header(header.0, header.1);
    }

    tracing::info!(
        code = format!("{}", res.status()),
        "Proxying response from upstream"
    );

    // modsecurity check headers, check response code

    let (downstream_body_reader, mut downstream_body_writer) = tokio::io::duplex(65536);

    let full_response = match full_response.body(
        StreamBody::new(ReaderStream::new(downstream_body_reader).map_ok(Frame::data)).boxed(),
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                code = 500,
                "Could not form response to upstream server: {e}"
            );

            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not form response to upstream server; this is an error with the proxy",
            );
        }
    };

    tokio::task::spawn({
        let span = Span::current();
        async move {
            let mut download_buffer = Vec::new();
            let mut res_body = res.into_body();

            if args.max_download_body_size == 0 {
                while let Some(next) = res_body.frame().await {
                    let Ok(frame) = next else {
                        tracing::error!("Broken reader connection");
                        break;
                    };

                    if let Some(chunk) = frame.data_ref() {
                        let Ok(_) = downstream_body_writer.write_all(chunk).await else {
                            tracing::error!("Broken writer connection");
                            break;
                        };
                    }
                }
            } else {
                let mut had_failure = false;
                while let Some(next) = res_body.frame().await {
                    let Ok(frame) = next else {
                        tracing::error!("Broken reader connection");
                        had_failure = true;
                        break;
                    };

                    tracing::trace!(
                        chunk = frame
                            .data_ref()
                            .clone()
                            .map(|c| c.deref().to_owned())
                            .and_then(|c| String::from_utf8(c).ok()),
                        "Received chunk"
                    );

                    if let Some(chunk) = frame.data_ref() {
                        tracing::trace!("Download buffer length before extending: {}", download_buffer.len());
                        download_buffer.extend_from_slice(chunk);
                        tracing::trace!("Download buffer length after extending: {}", download_buffer.len());

                        if download_buffer.len() > args.max_download_body_size * 1024 {
                            tracing::error!(
                                code = 413,
                                "Server response body exceeds configured maximum, exiting ({} > {})",
                                download_buffer.len(),
                                args.max_download_body_size
                            );
                            had_failure = true;
                            break;
                        }
                    }
                }

                if !had_failure {
                    // modsecurity check body

                    if let Err(e) = downstream_body_writer.write_all(&download_buffer).await {
                        tracing::error!(
                            code = 500,
                            "Could not write to downstrea body writer: {e}"
                        );
                    }
                }
            }
        }.instrument(span)
    });

    Ok(full_response)
}
