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
use tokio_util::io::ReaderStream;
use tracing::{Instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::utils::modsecurity::{ModSecurity, RulesSet, Transaction, CRS_DATA_FILES};

const CORE_RULESET_SETUP: &'static str = include_str!("proxy/core_ruleset.conf");

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

    /// Disable the use of modsecurity to watch traffic and scan for malicious activity
    #[arg(long, short)]
    disable_modsecurity: bool,

    /// Disable the bundled OWASP Core Rule Set
    #[arg(long)]
    disable_core_ruleset: bool,

    /// Dump rules after loading them
    #[arg(long, short = 'D')]
    dump_modsec_rules: bool,

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

    /// Configure the ModSecurity paranoia level. Goes from 1 to 4
    #[arg(long, short = 'p', default_value = "1")]
    msc_paranoia_level: u8,

    /// Configure the ModSecurity detection paranoia level; with ips_mode enabled, this will log violations at higher paranoia levels, but not act on them
    #[arg(long, short = 'P', default_value = "1")]
    msc_detect_paranoia_level: u8,
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

    let modsec = (!args.disable_modsecurity)
        .then(|| -> eyre::Result<_> {
            let mut modsec =
                ModSecurity::new("jj-rs proxy").ok_or(eyre::eyre!("Could not initialize modsecurity"))?;
            let mut rules =
                RulesSet::new().ok_or(eyre::eyre!("Could not initialize modsecurity rules set"))?;

            extern "C" fn log_responses(_: *mut std::ffi::c_void, msg: *const std::ffi::c_void) {
                use valuable::Valuable;
                
                let msg = msg as *const std::ffi::c_char;
                let msg = unsafe { std::ffi::CStr::from_ptr(msg) };
                let msg = msg.to_string_lossy();
                let msg = msg.to_string();

                let msg_chars = msg.chars().collect::<Vec<_>>();

                let mut meta = std::collections::HashMap::new();
                let mut in_brackets = false;
                let mut in_quotes = false;
                let mut end_index = msg.len() - 1;
                let mut working_index = end_index;
                let mut value_index = end_index;

                // checking against 1 allows risk free lookahead
                while end_index > 1 && working_index > 1 {
                    if msg_chars[working_index] == ']' && !in_brackets {
                        end_index = working_index;
                        in_brackets = true;
                    } else if msg_chars[working_index] == '"' && msg_chars[working_index - 1] != '\\' && !in_quotes {
                        in_quotes = true;
                    } else if msg_chars[working_index] == '"' && msg_chars[working_index - 1] != '\\' && in_quotes {
                        value_index = working_index;
                        in_quotes = false;
                    } else if msg_chars[working_index] == '[' && in_brackets && !in_quotes {
                        let key = msg[working_index + 1..value_index - 1].to_string();
                        let value = msg[value_index + 1..end_index - 1].to_string();
                        meta.insert(key, value);
                        in_brackets = false;
                    } else if msg_chars[working_index] != ' ' && !in_brackets && !in_quotes {
                        break;
                    }

                    working_index -= 1;
                }

                // modsecurity throws errors if the Host header is an IP address, but also throws errors
                // if the Host header is not set
                if Some("Host header is a numeric IP address") != meta.get("msg").map(String::as_str) {
                    tracing::warn!(meta = meta.as_value(), "{}", &msg[..working_index + 1]);
                }
            }
            modsec.set_log_callback(Some(log_responses));

            if !args.disable_core_ruleset {
                use rand::prelude::*;
                
                if args.ips_mode {
                    rules.add_rules("SecRuleEngine On")?;
                    rules.add_rules("SecRequestBodyAccess On")?;
                    rules.add_rules(r#"SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON""#)?;
                    rules.add_rules(r#"SecDefaultAction "phase:1,log,auditlog,deny,status:403""#)?;
                    rules.add_rules(r#"SecDefaultAction "phase:2,log,auditlog,deny,status:403""#)?;
                } else {
                    rules.add_rules("SecRuleEngine DetectionOnly")?;
                    rules.add_rules("SecRequestBodyAccess On")?;
                    rules.add_rules(r#"SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON""#)?;
                    rules.add_rules(r#"SecDefaultAction "phase:1,log,auditlog,pass"#)?;
                    rules.add_rules(r#"SecDefaultAction "phase:2,log,auditlog,pass"#)?;
                }

                rules.add_rules(&format!(r#"SecAction "id:900000,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.24',setvar:tx.blocking_paranoia_level={}""#, args.msc_paranoia_level))?;
                rules.add_rules(&format!(r#"SecAction "id:900000,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.24',setvar:tx.detection_paranoia_level={}""#, args.msc_detect_paranoia_level))?;

                rules.add_rules(CORE_RULESET_SETUP)?;

                let mut rng = rand::rng();
                let mut dir_name = "jj-rs-crs-".to_string();

                for _ in 0..10 {
                    dir_name.push(rng.sample(rand::distr::Alphanumeric) as char);
                }

                let mut tmp_dir = std::env::temp_dir();
                tmp_dir.push(dir_name);

                std::fs::create_dir_all(&tmp_dir)?;

                for (name, data) in CRS_DATA_FILES {
                    let mut tmp_file = tmp_dir.clone();
                    tmp_file.push(name);

                    let path = format!("{}/", tmp_dir.display()).replace('\\', "/");
                    std::fs::write(tmp_file, data.replace("@rules_dir", &path))?;
                }

                let mut names = CRS_DATA_FILES.iter().filter_map(|(name, _)| name.ends_with(".conf").then(|| name)).collect::<Vec<_>>();
                names.sort();
                for name in names {
                    let mut tmp_file = tmp_dir.clone();
                    tmp_file.push(name);

                    rules.add_file(tmp_file)?;
                }

                std::fs::remove_dir_all(tmp_dir)?;
            }

            if let Some(p) = &args.extra_rules {
                rules.add_file(p)?;
            }

            if args.dump_modsec_rules {
                rules.dump_rules();
            }

            if args.extra_rules.is_none() && args.disable_core_ruleset {
                tracing::warn!("Modsecurity enabled, but no extra rules were provided and core ruleset was disabled");
            }

            Ok(Some(Arc::new((modsec, rules))))
        })
        .unwrap_or(Ok(None))?;

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
    modsec: Option<Arc<(ModSecurity, RulesSet)>>,
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

fn msc_intervene(phase: &str, args: &Proxy, tx: &mut Transaction) -> (bool, Option<ServeResponse>) {
    match tx.intervention() {
        Some(it) => {
            use valuable::Valuable;

            let (log, meta) = it.log.map(|log| {
                let msg = log.to_string_lossy().to_string();
                let msg_chars = msg.chars().collect::<Vec<_>>();

                let mut meta = std::collections::HashMap::new();
                let mut in_brackets = false;
                let mut in_quotes = false;
                let mut end_index = msg.len() - 1;
                let mut working_index = end_index;
                let mut value_index = end_index;

                // checking against 1 allows risk free lookahead
                while end_index > 1 && working_index > 1 {
                    if msg_chars[working_index] == ']' && !in_brackets {
                        end_index = working_index;
                        in_brackets = true;
                    } else if msg_chars[working_index] == '"' && msg_chars[working_index - 1] != '\\' && !in_quotes {
                        in_quotes = true;
                    } else if msg_chars[working_index] == '"' && msg_chars[working_index - 1] != '\\' && in_quotes {
                        value_index = working_index;
                        in_quotes = false;
                    } else if msg_chars[working_index] == '[' && in_brackets && !in_quotes {
                        let key = msg[working_index + 1..value_index - 1].to_string();
                        let value = msg[value_index + 1..end_index - 1].to_string();
                        meta.insert(key, value);
                        in_brackets = false;
                    } else if msg_chars[working_index] != ' ' && !in_brackets && !in_quotes {
                        break;
                    }

                    working_index -= 1;
                }

                (msg[..working_index + 1].to_string(), meta)
            })
                .unwrap_or_default();

            tracing::warn!(
                phase = phase,
                pause = it.pause,
                disruptive = it.disruptive,
                status = it.status,
                url = format!("{:?}", &it.url),
                meta = meta.as_value(),
                "{}",
                log
            );

            if args.ips_mode && it.disruptive != 0 {
                (
                    true,
                    Some(err_response(
                        StatusCode::from_u16(it.status as u16).unwrap_or(StatusCode::FORBIDDEN),
                        ""
                    ))
                )
            } else {
                (false, None)
            }
        }
        None => {
            (false, None)
        }
    }
}

async fn respond_inner(
    args: Arc<Proxy>,
    req: Request<hyper::body::Incoming>,
    server: hyper::Uri,
    host: String,
    client: SocketAddr,
    modsec: Option<Arc<(ModSecurity, RulesSet)>>,
) -> ServeResponse {
    macro_rules! msc_intervene {
        ($phase:ident, $args:expr, $tx:expr) => {
            if let (true, Some(resp)) = msc_intervene(stringify!($phase), &$args, $tx) {
                return resp;
            }
        }
    }

    let mut msc_tx = modsec.as_ref().and_then(|msc| msc.0.new_transaction(&msc.1));

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

    if let Some(tx) = &mut msc_tx {
        tx.process_connection(&format!("{}", client.ip()), client.port(), &host, server.port_u16().unwrap_or(80));
        msc_intervene!(connection, args, tx);
        tx.process_uri(req.uri().path(), req.method().as_str(), &format!("{:?}", req.version()));
        msc_intervene!(uri, args, tx);
    }

    let mut upstream_req = Request::builder().uri(req.uri()).method(req.method()).version(req.version());

    for (name, value) in req.headers() {
        if args.override_host_header
            && (name == HeaderName::from_static("host")
                || name == HeaderName::from_static("x-forwarded-for"))
        {
            continue;
        }
        if let Some(tx) = &mut msc_tx && name != HeaderName::from_static("host") {
            tx.add_request_header(name.as_str().as_bytes(), value.as_bytes());
        }
        upstream_req = upstream_req.header(name, value);
    }

    let forwarded_addendum = if let Some(forwarded) = req.headers().get("x-forwarded-for")
        && let Ok(forwarded_str) = forwarded.to_str()
    {
        format!(", {forwarded_str}")
    } else {
        String::new()
    };
    upstream_req = upstream_req.header(
        "X-Forwarded-For",
        format!("{}{forwarded_addendum}", client.ip()),
    );
    let upstream_req = if args.override_host_header
        && let Some(host) = server.host()
    {
        upstream_req.header("Host", host)
    } else {
        upstream_req
    };

    if let Some(tx) = &mut msc_tx {
        let host_header = args.override_host_header
            .then(|| server.host().map(|h| h.as_bytes()))
            .unwrap_or_else(|| req.headers().get("host").map(|hdr| hdr.as_bytes()));

        if let Some(host_header) = host_header {
            let str_header = String::from_utf8_lossy(&host_header);
            if str_header.split(':').next().and_then(|ip| ip.parse::<Ipv4Addr>().ok()).is_none() {
                tx.add_request_header(b"host", host_header);
            } else {
                tx.add_request_header(b"host", b"ipaddr.local");
            }
        }

        tx.process_request_headers();
        msc_intervene!(request_headers, args, tx);
    }

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

    let res = tokio::task::spawn(async move { upstream_sender.send_request(upstream_req).await });

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

            tracing::trace!(
                chunk = frame
                    .data_ref()
                    .clone()
                    .map(|c| c.deref().to_owned())
                    .and_then(|c| String::from_utf8(c).ok()),
                "Received request chunk"
            );

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

            tracing::trace!(
                chunk = frame
                    .data_ref()
                    .clone()
                    .map(|c| c.deref().to_owned())
                    .and_then(|c| String::from_utf8(c).ok()),
                "Received request chunk"
            );

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

        if let Some(tx) = &mut msc_tx {
            tx.append_request_body(&body_buffer);
            tx.process_request_body();
            msc_intervene!(request_body, args, tx);
        }

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

    let mut full_response = Response::builder().status(res.status()).version(res.version()).status(res.status());
    for (name, value) in res.headers() {
        if let Some(tx) = &mut msc_tx {
            tx.add_response_header(name.as_str().as_bytes(), value.as_bytes());
        }
        full_response = full_response.header(name, value);
    }

    if let Some(tx) = &mut msc_tx {
        let version = format!("{:?}", res.version());
        tx.process_response_headers(res.status().as_u16(), &version.split('/').last().map(|v| format!("HTTP {v}")).unwrap_or(version));
        msc_intervene!(response_headers, args, tx);
    }

    tracing::info!(
        code = format!("{}", res.status()),
        "Proxying response from upstream"
    );

    if args.max_download_body_size == 0 {
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

        if let Some(tx) = &mut msc_tx {
            tx.process_response_body();
            msc_intervene!(response_body, args, tx);
            tx.process_logging();
            msc_intervene!(logging, args, tx);
        }

        tokio::task::spawn({
            let span = Span::current();
            async move {
                let mut res_body = res.into_body();
                while let Some(next) = res_body.frame().await {
                    let Ok(frame) = next else {
                        tracing::error!("Broken reader connection");
                        break;
                    };

                    tracing::trace!(
                        chunk = frame
                            .data_ref()
                            .clone()
                            .map(|c| c.deref().to_owned())
                            .and_then(|c| String::from_utf8(c).ok()),
                        "Received response chunk"
                    );

                    if let Some(chunk) = frame.data_ref() {
                        let Ok(_) = downstream_body_writer.write_all(chunk).await else {
                            tracing::error!("Broken writer connection");
                            break;
                        };
                    }
                }
            }
            .instrument(span)
        });

        Ok(full_response)
    } else {
        let mut download_buffer = Vec::new();

        let mut res_body = res.into_body();

        while let Some(next) = res_body.frame().await {
            let frame = match next {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(code = 502, "Broken reader connection: {e}");
                    return err_response(StatusCode::BAD_GATEWAY, "Broken reader connection");
                }
            };

            // tracing::trace!(
            //     chunk = frame
            //         .data_ref()
            //         .clone()
            //         .map(|c| c.deref().to_owned())
            //         .and_then(|c| String::from_utf8(c).ok()),
            //     "Received response chunk"
            // );

            if let Some(chunk) = frame.data_ref() {
                // tracing::trace!(
                //     "Download buffer length before extending: {}",
                //     download_buffer.len()
                // );
                download_buffer.extend_from_slice(chunk);
                // tracing::trace!(
                //     "Download buffer length after extending: {}",
                //     download_buffer.len()
                // );

                if download_buffer.len() > args.max_download_body_size * 1024 {
                    tracing::error!(
                        code = 413,
                        "Server response body exceeds configured maximum, exiting ({} > {})",
                        download_buffer.len(),
                        args.max_download_body_size
                    );
                    return err_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Server response body exceeds maximum configuration",
                    );
                }
            }
        }

        if let Some(tx) = &mut msc_tx {
            tx.append_response_body(&download_buffer);
            tx.process_response_body();
            msc_intervene!(response_body, args, tx);
            tx.process_logging();
            msc_intervene!(logging, args, tx);
        }

        let body = Full::new(Bytes::from(download_buffer))
            .map_err(std::io::Error::other)
            .boxed();

        Ok(full_response.body(body)?)
    }
}
