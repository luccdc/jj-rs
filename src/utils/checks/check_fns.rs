//! Not all checks have to be reimplemented from the ground up. This module
//! includes building blocks for applying simple checks or applying filters
//! to checks

use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
};

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::utils::{
    checks::{CheckResult, CheckStep, IntoCheckResult, TroubleshooterRunner},
    distro::Distro,
    download_container::DownloadContainer,
    qx,
    systemd::{get_service_info, is_service_active},
};

#[doc(hidden)]
pub struct CheckFn<'a, F>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    name: &'static str,
    check_fn: F,
    _lifetime: PhantomData<&'a F>,
}

impl<'a, F> CheckStep<'a> for CheckFn<'a, F>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn run_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        (self.check_fn)(tr)
    }
}

/// Convert a simple function to a troubleshooting check step
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, check_fn};
/// check_fn(
///     "Always return true",
///     |_| {
///         Ok(CheckResult::succeed(
///             "Check has returned true",
///             serde_json::json!(null)
///         ))
///     }
/// );
/// ```
pub fn check_fn<'a, F>(name: &'static str, f: F) -> Box<dyn CheckStep<'a> + 'a>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    Box::new(CheckFn {
        name,
        check_fn: f,
        _lifetime: PhantomData,
    })
}

/// Control whether or not run the underlying check for [`filter_check`] or [`filter_check_when`]
/// is run or not run with the provided error message
pub enum CheckFilterResult {
    Run,
    NoRun(String),
}

pub trait IntoCheckFilterResult {
    fn into_check_filter_result(self) -> CheckFilterResult;
}

impl IntoCheckFilterResult for CheckFilterResult {
    fn into_check_filter_result(self) -> CheckFilterResult {
        self
    }
}

impl IntoCheckFilterResult for Option<CheckFilterResult> {
    fn into_check_filter_result(self) -> CheckFilterResult {
        self.unwrap_or(CheckFilterResult::Run)
    }
}

impl<E, I> IntoCheckFilterResult for Result<I, E>
where
    E: std::fmt::Debug,
    I: IntoCheckFilterResult,
{
    fn into_check_filter_result(self) -> CheckFilterResult {
        match self {
            Ok(v) => v.into_check_filter_result(),
            Err(e) => CheckFilterResult::NoRun(format!(
                "Could not decide whether or not to run check: {e:?}"
            )),
        }
    }
}

#[doc(hidden)]
pub struct CheckFilter<'a, F, T>
where
    F: Fn(Option<Distro>) -> T + 'a,
{
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
}

/// Allows applying a filter to a check, only running the underlying check
/// if the filter applied matches
///
/// The filter function takes as a parameter the current Linux distribution
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, CheckFilterResult, check_fn, filter_check_when};
/// filter_check_when(
///     check_fn(
///         "Always return true",
///         |_| {
///             Ok(CheckResult::succeed(
///                 "Check has returned true",
///                 serde_json::json!(null)
///             ))
///         }
///     ),
///     |distro| Ok::<_, ()>(if distro.map(|d| d.is_deb_based()).unwrap_or(false) {
///         CheckFilterResult::Run
///     } else {
///         CheckFilterResult::NoRun("Test not designed for non-Debian systems".into())
///     })
/// );
/// ```
pub fn filter_check_when<'a, F, T>(
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
) -> Box<dyn CheckStep<'a> + 'a>
where
    F: Fn(Option<Distro>) -> T + 'a,
    T: IntoCheckFilterResult + 'a,
{
    Box::new(CheckFilter { check, filter_func })
}

/// Runs the check only when the provided input is true. Uses the message provided if the
/// boolean expression results in false
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, check_fn, filter_check};
/// filter_check(
///     check_fn(
///         "Always return true",
///         |_| {
///             Ok(CheckResult::succeed(
///                 "Check has returned true",
///                 serde_json::json!(null)
///             ))
///         }
///     ),
///     false,
///     "Always not run"
/// );
/// ```
pub fn filter_check<'a, I: Into<String> + Clone + 'a>(
    check: Box<dyn CheckStep<'a> + 'a>,
    predicate: bool,
    message: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    filter_check_when(check, move |_| {
        if predicate {
            CheckFilterResult::Run
        } else {
            CheckFilterResult::NoRun(message.clone().into())
        }
    })
}

impl<'a, F, T> CheckStep<'a> for CheckFilter<'a, F, T>
where
    F: Fn(Option<Distro>) -> T + 'a,
    T: IntoCheckFilterResult + 'a,
{
    fn name(&self) -> &'static str {
        self.check.name()
    }

    fn run_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let distro = crate::utils::distro::get_distro()?;
        match (self.filter_func)(distro).into_check_filter_result() {
            CheckFilterResult::Run => self.check.run_check(tr),
            CheckFilterResult::NoRun(v) => Ok(CheckResult::not_run(v, serde_json::json!(null))),
        }
    }
}

#[doc(hidden)]
pub struct SystemdServiceCheck {
    service_name: String,
}

impl<'a> CheckStep<'a> for SystemdServiceCheck {
    fn name(&self) -> &'static str {
        "Check systemd service"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if qx("which systemctl 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`systemctl` not found on host",
                serde_json::json!(null),
            ));
        }

        let service_info = get_service_info(&self.service_name)?;

        if is_service_active(&service_info) {
            Ok(CheckResult::succeed(
                "systemd service is active",
                serde_json::json!({
                   "main_pid": service_info.get("MainPID"),
                   "running_since": service_info.get("ExecMainStartTimestamp")
                }),
            ))
        } else {
            Ok(CheckResult::fail(
                "systemd service is not active",
                serde_json::json!({
                   "stopped_since": service_info.get("InactiveEnterTimestamp")
                }),
            ))
        }
    }
}

/// A simple check that makes sure a systemd service is up. Provides
/// as context when the server went up or down as well as the PID if it
/// is running
///
/// ```
/// # use jj_rs::utils::checks::systemd_service_check;
/// systemd_service_check("ssh");
/// ```
pub fn systemd_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(SystemdServiceCheck {
        service_name: name.into(),
    })
}

#[doc(hidden)]
pub struct OpenrcServiceCheck {
    service_name: String,
}

impl<'a> CheckStep<'a> for OpenrcServiceCheck {
    fn name(&self) -> &'static str {
        "Check openrc service"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if qx("which rc-service 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`rc-service` not found on host",
                serde_json::json!(null),
            ));
        }

        let res = qx(&format!("rc-service {} status", &self.service_name))?.1;

        if res.contains("status: started") {
            Ok(CheckResult::succeed(
                "OpenRC service is active",
                serde_json::json!(null),
            ))
        } else {
            Ok(CheckResult::fail(
                "OpenRC service is not active",
                serde_json::json!(null),
            ))
        }
    }
}

/// A simple check that makes sure an OpenRC service is up
///
/// ```
/// # use jj_rs::utils::checks::openrc_service_check;
/// openrc_service_check("ssh");
/// ```
pub fn openrc_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(OpenrcServiceCheck {
        service_name: name.into(),
    })
}

#[doc(hidden)]
pub struct TcpConnectCheck {
    ip: IpAddr,
    port: u16,
}

impl<'a> CheckStep<'a> for TcpConnectCheck {
    fn name(&self) -> &'static str {
        "Check to see if the port is accessible for TCP"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let timeout = std::time::Duration::from_secs(2);

        if self.ip.is_loopback() {
            let cont = DownloadContainer::new(None, None)?;
            let client1 = cont.run(|| {
                let addr = SocketAddr::new(IpAddr::V4(cont.wan_ip()), self.port);
                TcpStream::connect_timeout(&addr, timeout).map(|_| ())
            })?;
            let addr2 = SocketAddr::new(self.ip, self.port);
            let client2 = TcpStream::connect_timeout(&addr2, timeout).map(|_| ());

            Ok(match (client1, client2) {
                (Ok(_), Ok(_)) => CheckResult::succeed(
                    format!(
                        "Successfully connected to {}:{} and successfully connected to {} from download container",
                        self.ip, self.port, self.port
                    ),
                    serde_json::json!(null),
                ),
                (Ok(_), Err(e)) => CheckResult::fail(
                    format!(
                        "Failed to connect to {}:{}, but successfully connected to port {} from the download shell",
                        self.ip, self.port, self.port
                    ),
                    serde_json::json!({
                        "local_connection_error": format!("{e:?}")
                    }),
                ),
                (Err(e), Ok(_)) => CheckResult::fail(
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
            let cont = DownloadContainer::new(None, None)?;
            let addr = SocketAddr::new(self.ip, self.port);
            let client = cont.run(|| TcpStream::connect_timeout(&addr, timeout).map(|_| ()))?;

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
}

/// A simple check that sees if a service port is open and responding to TCP requests
pub fn tcp_connect_check<'a, I: Into<IpAddr>>(addr: I, port: u16) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(TcpConnectCheck {
        ip: addr.into(),
        port,
    })
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum TcpdumpProtocol {
    Tcp,
    Udp,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct TcpdumpCheck {
    ip: Ipv4Addr,
    port: u16,
    protocol: TcpdumpProtocol,
    connection_test: Vec<u8>,
    local: bool,
}

struct TcpdumpCodec;

impl pcap::PacketCodec for TcpdumpCodec {
    type Item = (pcap::PacketHeader, Vec<u8>);

    fn decode(&mut self, p: pcap::Packet<'_>) -> Self::Item {
        (p.header.clone(), p.data.to_owned())
    }
}

impl TcpdumpCheck {
    fn setup_check_watch(&self) -> anyhow::Result<pcap::PacketStream<pcap::Active, TcpdumpCodec>> {
        let device =
            pcap::Device::lookup()?.ok_or(anyhow::anyhow!("Could not find pcap device"))?;

        let capture = pcap::Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            .timeout(10);

        let mut capture = capture.open()?.setnonblock()?;
        capture.filter(
            &format!(
                "host {} and {} port {}",
                self.ip,
                match &self.protocol {
                    TcpdumpProtocol::Tcp => {
                        "tcp"
                    }
                    TcpdumpProtocol::Udp { .. } => {
                        "udp"
                    }
                },
                self.port
            ),
            false,
        )?;

        Ok(capture.stream(TcpdumpCodec)?)
    }

    async fn run_check_watch(
        &self,
        capture: &mut pcap::PacketStream<pcap::Active, TcpdumpCodec>,
    ) -> anyhow::Result<u16> {
        let mut source_port = None::<u16>;
        let mut source_addr = None::<Ipv4Addr>;

        loop {
            let Some(Ok((header, packet))) = capture.next().await else {
                continue;
            };

            // 14: Ethernet header
            // 20: IPv4 header
            // 4: TCP/UDP src/destination ports
            // 10: seq/ack/flags for TCP
            // We don't need any extra information from UDP, but from TCP we want flags to check for
            // SYN/ACK
            if let Some(port) = match self.protocol {
                TcpdumpProtocol::Udp => (header.caplen >= 38)
                    .then(|| self.check_udp_packet(&mut source_port, &mut source_addr, &packet))
                    .flatten(),
                TcpdumpProtocol::Tcp => (header.caplen >= 48)
                    .then(|| self.check_tcp_packet(&mut source_port, &mut source_addr, &packet))
                    .flatten(),
            } {
                return Ok(port);
            }
        }
    }

    fn check_tcp_packet(
        &self,
        source_port: &mut Option<u16>,
        source_addr: &mut Option<Ipv4Addr>,
        packet: &[u8],
    ) -> Option<u16> {
        if packet[30..34] == u32::from(self.ip).to_be_bytes()
            && packet[36..38] == self.port.to_be_bytes()
        {
            let offset = ((packet[46] as usize) & 0xF0).overflowing_shr(4).0;
            let offset = 34 + offset * 4;

            if packet.len() - offset < self.connection_test.len() {
                None?;
            }

            if &packet[offset..] == self.connection_test {
                *source_port = Some(u16::from_be_bytes([packet[34], packet[35]]));
                *source_addr = Some(Ipv4Addr::from_octets([
                    packet[26], packet[27], packet[28], packet[29],
                ]));
            }

            None
        } else {
            let (Some(source_port), Some(source_addr)) = (source_port, source_addr) else {
                return None;
            };

            (packet[26..30] == u32::from(self.ip).to_be_bytes()
                && packet[34..36] == self.port.to_be_bytes()
                && packet[30..34] == u32::from(*source_addr).to_be_bytes()
                && packet[36..38] == source_port.to_be_bytes())
            .then(|| *source_port)
        }
    }

    fn check_udp_packet(
        &self,
        source_port: &mut Option<u16>,
        source_addr: &mut Option<Ipv4Addr>,
        packet: &[u8],
    ) -> Option<u16> {
        if packet[30..34] == u32::from(self.ip).to_be_bytes()
            && packet[36..38] == self.port.to_be_bytes()
        {
            let offset = 38;

            if packet.len() - offset < self.connection_test.len() {
                None?;
            }

            if &packet[offset..] == self.connection_test {
                *source_port = Some(u16::from_be_bytes([packet[34], packet[35]]));
                *source_addr = Some(Ipv4Addr::from_octets([
                    packet[26], packet[27], packet[28], packet[29],
                ]));
            }

            None
        } else {
            let (Some(source_port), Some(source_addr)) = (source_port, source_addr) else {
                return None;
            };

            (packet[26..30] == u32::from(self.ip).to_be_bytes()
                && packet[34..36] == self.port.to_be_bytes()
                && packet[30..34] == u32::from(*source_addr).to_be_bytes()
                && packet[36..38] == source_port.to_be_bytes())
            .then(|| *source_port)
        }
    }

    async fn run_check_input(&self) -> anyhow::Result<u16> {
        use TcpdumpProtocol as TCT;
        let TcpdumpCheck {
            connection_test,
            ip,
            port,
            protocol,
            ..
        } = self;

        match protocol {
            TCT::Tcp => {
                let mut sock = tokio::net::TcpStream::connect((*ip, *port)).await?;
                sock.write(connection_test).await?;
                Ok(sock.local_addr()?.port())
            }
            TCT::Udp => {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                sock.send_to(&connection_test, (*ip, *port)).await?;
                Ok(sock.local_addr()?.port())
            }
        }
    }

    async fn check_local(&self) -> anyhow::Result<CheckResult> {
        // make a container and run checks from the container
        let cont = DownloadContainer::new(None, None)?;
        let wan_ip = cont.wan_ip();

        unsafe { cont.enter() }?;

        let check = TcpdumpCheck {
            ip: wan_ip,
            ..self.clone()
        };

        let v = check.check_remote().await;
        cont.leave()?;
        v
    }

    async fn check_remote(&self) -> anyhow::Result<CheckResult> {
        // Check against a remote server that does NAT reflection

        let mut capture = self.setup_check_watch()?;

        // poll watch once, so that it can get to the point where it is ready
        for attempt in 0..3 {
            use tokio::time;
            let src_port = time::timeout(time::Duration::from_secs(4), self.run_check_input());

            let guess_port = time::timeout(
                time::Duration::from_secs(2),
                self.run_check_watch(&mut capture),
            );

            let (Ok(Ok(guess_port)), Ok(Ok(src_port))) = tokio::join!(guess_port, src_port) else {
                continue;
            };

            if guess_port == src_port {
                return Ok(CheckResult::succeed(
                    "Successfully verified that the firewall is allowing inbound traffic on service port with tcpdump",
                    serde_json::json!({ "attempt_count": attempt + 1 }),
                ));
            }
        }

        Ok(CheckResult::fail(
            "Could not verify firewall with tcpdump after 3 attempts",
            serde_json::json!(null),
        ))
    }
}

impl<'a> CheckStep<'a> for TcpdumpCheck {
    fn name(&self) -> &'static str {
        "Check tcpdump to verify the firewall is working"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        match (self.local, self.ip.is_loopback()) {
            (true, _) => {}
            (false, false) => {
                return Ok(CheckResult::not_run(
                    "Cannot check tcpdump when packets do not return to system via NAT reflection"
                        .to_string(),
                    serde_json::json!(null),
                ));
            }
            (false, true) => {
                return Ok(CheckResult::not_run(
                    "Cannot check tcpdump on localhost".to_string(),
                    serde_json::json!(null),
                ));
            }
        }

        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                if self.ip.is_loopback() {
                    self.check_local().await
                } else {
                    self.check_remote().await
                }
            })
            .into_check_result("Unknown error when performing tcpdump check"))
    }
}

/// A check that tries to see if packets are able to leave and come back. Only works for checks
/// where NAT reflection is being used, to allow traffic to leave and go to a specific IP but have
/// the server reflect the traffic back to the local system. Can be considered a much more advanced
/// version of the TcpConnectCheck
pub fn tcpdump_check<'a, I: Into<Ipv4Addr>>(
    addr: I,
    port: u16,
    protocol: TcpdumpProtocol,
    connection_test: Vec<u8>,
    local: bool,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(TcpdumpCheck {
        ip: addr.into(),
        port,
        protocol,
        connection_test,
        local,
    })
}
