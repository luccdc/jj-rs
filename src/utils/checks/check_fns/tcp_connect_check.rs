use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};

use eyre::{Context, eyre};

use crate::utils::checks::{CheckResult, CheckStep, TroubleshooterRunner};
use crate::utils::clap::Host;

#[cfg(unix)]
use crate::utils::download_container::DownloadContainer;

struct TcpConnectCheck {
    addr: SocketAddr,
    #[cfg_attr(windows, allow(unused))]
    avoid_download_container: bool,
    #[cfg_attr(windows, allow(unused))]
    download_container_ip: Option<Ipv4Addr>,
}

impl TcpConnectCheck {}

impl CheckStep<'_> for TcpConnectCheck {
    fn name(&self) -> &'static str {
        "Check TCP port status"
    }

    #[cfg(unix)]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let timeout = std::time::Duration::from_secs(2);

        if self.avoid_download_container {
            let addr = SocketAddr::new(self.addr.ip(), self.addr.port());
            let client = TcpStream::connect_timeout(&addr, timeout).map(|_| ());

            if let Err(e) = client {
                Ok(CheckResult::fail(
                    format!(
                        "Could not connect to {}:{}",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "error": format!("{e:?}")
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    format!(
                        "Successfully connected to {}:{}",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!(null),
                ))
            }
        } else if self.addr.ip().is_loopback() {
            use crate::utils::checks::CheckResultType as CRT;

            let cont = DownloadContainer::new(None, self.download_container_ip)
                .context("Could not create download container for TCP check");
            let client1 = cont.and_then(|cont| {
                cont.run(|| {
                    let addr = SocketAddr::new(IpAddr::V4(cont.wan_ip()), self.addr.port());
                    TcpStream::connect_timeout(&addr, timeout).map(|_| ())
                })
                .context("Could not run TCP connection test in download container")
            });
            let client2 = TcpStream::connect_timeout(&self.addr, timeout).map(|_| ());

            let timestamp = chrono::Utc::now();

            let (result1, message1, json1) = match client1 {
                Ok(Ok(())) => (
                    CRT::Success,
                    format!(
                        "Successfully connected to {}:{} from download container",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({}),
                ),
                Ok(Err(e)) => (
                    CRT::Failure,
                    format!(
                        "Failed to connect to {}:{} from download container",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "container_error": format!("{e}")
                    }),
                ),
                Err(e) => (
                    CRT::Warning,
                    format!(
                        "Failed to create download container to connect to {}:{}",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "container_create_error": format!("{e}")
                    }),
                ),
            };

            let (result2, message2, json2) = match client2 {
                Ok(()) => (
                    CRT::Success,
                    format!("successfully connected directly"),
                    serde_json::json!({}),
                ),
                Err(e) => (
                    CRT::Failure,
                    format!("failed to connect directly"),
                    serde_json::json!({
                        "direct_error": format!("{e}")
                    }),
                ),
            };

            let extra_details = match (json1, json2) {
                (serde_json::Value::Object(mut m1), serde_json::Value::Object(m2)) => {
                    m1.extend(m2);
                    serde_json::Value::Object(m1)
                }
                (_, json2) => json2,
            };

            Ok(CheckResult {
                log_item: format!(
                    "{message1} {} {message2}",
                    if result1 == result2 { "and" } else { "but" }
                ),
                timestamp,
                extra_details,
                result_type: result1 | result2,
            })
        } else {
            let cont = match DownloadContainer::new(None, self.download_container_ip) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(CheckResult::warn(
                        "Could not create download container",
                        serde_json::json!({"download_container_error": format!("{e}")}),
                    ));
                }
            };
            let addr = SocketAddr::new(self.addr.ip(), self.addr.port());
            let client = cont
                .run(|| TcpStream::connect_timeout(&addr, timeout).map(|_| ()))
                .context("Could not run TCP connection test in download container")?;

            if let Err(e) = client {
                Ok(CheckResult::fail(
                    format!(
                        "Could not connect to {}:{}",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "error": format!("{e:?}")
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    format!(
                        "Successfully connected to {}:{}",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!(null),
                ))
            }
        }
    }

    #[cfg(windows)]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let timeout = std::time::Duration::from_secs(2);

        let client = TcpStream::connect_timeout(&self.addr, timeout).map(|_| ());

        if let Err(e) = client {
            Ok(CheckResult::fail(
                format!(
                    "Could not connect to {}:{}",
                    self.addr.ip(),
                    self.addr.port()
                ),
                serde_json::json!({
                    "error": format!("{e:?}")
                }),
            ))
        } else {
            Ok(CheckResult::succeed(
                format!(
                    "Successfully connected to {}:{}",
                    self.addr.ip(),
                    self.addr.port()
                ),
                serde_json::json!(null),
            ))
        }
    }
}

/// A simple check that sees if a service port is open and responding to TCP requests
pub fn tcp_connect_check<'a, I: Into<IpAddr>>(
    host: I,
    port: u16,
    avoid_download_container: bool,
    download_container_ip: Option<Ipv4Addr>,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(TcpConnectCheck {
        addr: SocketAddr::from((host, port)),
        avoid_download_container,
        download_container_ip,
    })
}

pub fn tcp_connect_check_dns<'a, H: Into<Host>>(
    host: H,
    port: u16,
    avoid_download_container: bool,
    download_container_ip: Option<Ipv4Addr>,
) -> eyre::Result<Box<dyn CheckStep<'a> + 'a>> {
    match host.into() {
        // assuming Into<Host> is infallible
        Host::Ip(ip) => Ok(Box::new(TcpConnectCheck {
            addr: SocketAddr::from((ip, port)),
            avoid_download_container,
            download_container_ip,
        })),

        Host::Domain(host) => {
            let mut addrs = (host.as_str(), port)
                .to_socket_addrs()
                .context("Failed to resolve hostname")?;

            let addr = addrs
                .next()
                .ok_or_else(|| eyre!("Hostname does not resolve to any IP address"))?;

            Ok(Box::new(TcpConnectCheck {
                addr,
                avoid_download_container,
                download_container_ip,
            }))
        }
    }
}
