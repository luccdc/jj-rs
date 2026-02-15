use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

use eyre::Context;

use crate::utils::checks::{CheckResult, CheckStep, TroubleshooterRunner};

#[cfg(unix)]
use crate::utils::download_container::DownloadContainer;

struct TcpConnectCheck {
    ip: IpAddr,
    port: u16,
    #[cfg_attr(windows, allow_unused)]
    avoid_download_container: bool,
    #[cfg_attr(windows, allow_unused)]
    download_container_ip: Option<Ipv4Addr>,
}

impl CheckStep<'_> for TcpConnectCheck {
    fn name(&self) -> &'static str {
        "Check TCP port status"
    }

    #[cfg(unix)]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let timeout = std::time::Duration::from_secs(2);

        if self.avoid_download_container {
            let addr = SocketAddr::new(self.ip, self.port);
            let client = TcpStream::connect_timeout(&addr, timeout).map(|_| ());

            if let Err(e) = client {
                Ok(CheckResult::fail(
                    format!("Could not connect to {}:{}", self.ip, self.port),
                    serde_json::json!({
                        "error": format!("{e:?}")
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    format!("Successfully connected to {}:{}", self.ip, self.port),
                    serde_json::json!(null),
                ))
            }
        } else if self.ip.is_loopback() {
            let cont = DownloadContainer::new(None, self.download_container_ip)
                .context("Could not create download container for TCP check")?;
            let client1 = cont
                .run(|| {
                    let addr = SocketAddr::new(IpAddr::V4(cont.wan_ip()), self.port);
                    TcpStream::connect_timeout(&addr, timeout).map(|_| ())
                })
                .context("Could not run TCP connection test in download container")?;
            let addr2 = SocketAddr::new(self.ip, self.port);
            let client2 = TcpStream::connect_timeout(&addr2, timeout).map(|_| ());

            Ok(match (client1, client2) {
                (Ok(()), Ok(())) => CheckResult::succeed(
                    format!(
                        "Successfully connected to {}:{} and successfully connected to {} from download container",
                        self.ip, self.port, self.port
                    ),
                    serde_json::json!(null),
                ),
                (Ok(()), Err(e)) => CheckResult::fail(
                    format!(
                        "Failed to connect to {}:{}, but successfully connected to port {} from the download shell",
                        self.ip, self.port, self.port
                    ),
                    serde_json::json!({
                        "local_connection_error": format!("{e:?}")
                    }),
                ),
                (Err(e), Ok(())) => CheckResult::fail(
                    format!(
                        "Successfully connected to {}:{}, but failed to connect to port {} from the download container",
                        self.ip, self.port, self.port
                    ),
                    serde_json::json!({
                        "container_connection_error": format!("{e:?}")
                    }),
                ),
                (Err(e1), Err(e2)) => CheckResult::fail(
                    format!(
                        "Failed to connect to {}:{} and failed from the download container",
                        self.ip, self.port
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
            let addr = SocketAddr::new(self.ip, self.port);
            let client = cont
                .run(|| TcpStream::connect_timeout(&addr, timeout).map(|_| ()))
                .context("Could not run TCP connection test in download container")?;

            if let Err(e) = client {
                Ok(CheckResult::fail(
                    format!("Could not connect to {}:{}", self.ip, self.port),
                    serde_json::json!({
                        "error": format!("{e:?}")
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    format!("Successfully connected to {}:{}", self.ip, self.port),
                    serde_json::json!(null),
                ))
            }
        }
    }

    #[cfg(windows)]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let timeout = std::time::Duration::from_secs(2);

        let addr = SocketAddr::new(self.ip, self.port);
        let client = TcpStream::connect_timeout(&addr, timeout).map(|_| ());

        if let Err(e) = client {
            Ok(CheckResult::fail(
                format!("Could not connect to {}:{}", self.ip, self.port),
                serde_json::json!({
                    "error": format!("{e:?}")
                }),
            ))
        } else {
            Ok(CheckResult::succeed(
                format!("Successfully connected to {}:{}", self.ip, self.port),
                serde_json::json!(null),
            ))
        }
    }
}

/// A simple check that sees if a service port is open and responding to TCP requests
pub fn tcp_connect_check<'a, I: Into<IpAddr>>(
    addr: I,
    port: u16,
    avoid_download_container: bool,
    download_container_ip: Option<Ipv4Addr>,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(TcpConnectCheck {
        ip: addr.into(),
        port,
        avoid_download_container,
        download_container_ip,
    })
}
