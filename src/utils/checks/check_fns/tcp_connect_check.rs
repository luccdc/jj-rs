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
            let cont = DownloadContainer::new(None, self.download_container_ip)
                .context("Could not create download container for TCP check")?;
            let client1 = cont
                .run(|| {
                    let addr = SocketAddr::new(IpAddr::V4(cont.wan_ip()), self.addr.port());
                    TcpStream::connect_timeout(&addr, timeout).map(|_| ())
                })
                .context("Could not run TCP connection test in download container")?;
            let client2 = TcpStream::connect_timeout(&self.addr, timeout).map(|_| ());

            Ok(match (client1, client2) {
                (Ok(()), Ok(())) => CheckResult::succeed(
                    format!(
                        "Successfully connected to {}:{} and successfully connected to {} from download container",
                        self.addr.ip(),
                        self.addr.port(),
                        self.addr.port()
                    ),
                    serde_json::json!(null),
                ),
                (Ok(()), Err(e)) => CheckResult::fail(
                    format!(
                        "Failed to connect to {}:{}, but successfully connected to port {} from the download shell",
                        self.addr.ip(),
                        self.addr.port(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "local_connection_error": format!("{e:?}")
                    }),
                ),
                (Err(e), Ok(())) => CheckResult::fail(
                    format!(
                        "Successfully connected to {}:{}, but failed to connect to port {} from the download container",
                        self.addr.ip(),
                        self.addr.port(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "container_connection_error": format!("{e:?}")
                    }),
                ),
                (Err(e1), Err(e2)) => CheckResult::fail(
                    format!(
                        "Failed to connect to {}:{} and failed from the download container",
                        self.addr.ip(),
                        self.addr.port()
                    ),
                    serde_json::json!({
                        "container_connection_error": format!("{e1:?}"),
                        "local_connection_error": format!("{e2:?}"),
                    }),
                ),
            })
        } else {
            let cont = DownloadContainer::new(None, self.download_container_ip)
                .context("Could not create download container for TCP check")?;
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
