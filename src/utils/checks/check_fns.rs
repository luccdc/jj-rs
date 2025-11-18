//! Not all checks have to be reimplemented from the ground up. This module
//! includes building blocks for applying simple checks or applying filters
//! to checks

use std::{
    io::prelude::*,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
};

use anyhow::Context;
use futures_util::StreamExt;

use crate::utils::{
    busybox::Busybox,
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
        let distro = crate::utils::distro::get_distro().context(
            "Could not query current Linux distribution to determine if a check should run",
        )?;
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

        let service_info = get_service_info(&self.service_name)
            .context("Could not pull systemd service information")?;

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

        let res = qx(&format!("rc-service {} status", &self.service_name))
            .context("Could not pull openrc service information")?
            .1;

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
            let cont = DownloadContainer::new(None, None)
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
            let cont = DownloadContainer::new(None, None)
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
}

/// A simple check that sees if a service port is open and responding to TCP requests
pub fn tcp_connect_check<'a, I: Into<IpAddr>>(addr: I, port: u16) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(TcpConnectCheck {
        ip: addr.into(),
        port,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[allow(dead_code)]
pub enum TcpdumpProtocol {
    Tcp,
    Udp,
}

impl TcpdumpProtocol {
    fn from_int(i: u8) -> Option<Self> {
        match i {
            6 => Some(TcpdumpProtocol::Tcp),
            17 => Some(TcpdumpProtocol::Udp),
            _ => None,
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct ImmediateTcpdumpCheck {
    port: u16,
    protocol: TcpdumpProtocol,
    connection_test: Vec<u8>,
    should_run: bool,
}

struct TcpdumpCodec;

impl pcap::PacketCodec for TcpdumpCodec {
    type Item = (pcap::PacketHeader, Vec<u8>);

    fn decode(&mut self, p: pcap::Packet<'_>) -> Self::Item {
        (p.header.clone(), p.data.to_owned())
    }
}

impl ImmediateTcpdumpCheck {
    fn setup_check_watch(
        &self,
        wan_ip: Ipv4Addr,
        lan_device: &str,
    ) -> anyhow::Result<pcap::PacketStream<pcap::Active, TcpdumpCodec>> {
        let device = pcap::Device::list()
            .context("Could not list pcap devices")?
            .into_iter()
            .find(|dev| dev.name == lan_device)
            .ok_or(anyhow::anyhow!("Could not find pcap device"))?;

        let capture = pcap::Capture::from_device(device)
            .context("Could not load packet capture device for tcpdump check")?
            .promisc(true)
            .immediate_mode(true)
            .timeout(10);

        let mut capture = capture
            .open()
            .context("Could not open packet capture device for tcpdump check")?
            .setnonblock()
            .context(
                "Could not convert packet capture device to non blocking mode for tcpdump check",
            )?;
        capture
            .filter(
                &format!(
                    "host {} and {} port {}",
                    wan_ip,
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
            )
            .context("Could not set filter for tcpdump check")?;

        Ok(capture
            .stream(TcpdumpCodec)
            .context("Could not convert capture device to stream for tcpdump check")?)
    }

    async fn run_check_watch(
        &self,
        source_port: &mut Option<u16>,
        source_addr: &mut Option<Ipv4Addr>,
        wan_ip: Ipv4Addr,
        inbound_packet_count: &mut usize,
        outbound_packet_count: &mut usize,
        capture: &mut pcap::PacketStream<pcap::Active, TcpdumpCodec>,
    ) -> anyhow::Result<u16> {
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
                    .then(|| {
                        self.check_udp_packet(
                            source_port,
                            source_addr,
                            wan_ip,
                            inbound_packet_count,
                            outbound_packet_count,
                            &packet,
                        )
                    })
                    .flatten(),
                TcpdumpProtocol::Tcp => (header.caplen >= 48)
                    .then(|| {
                        self.check_tcp_packet(
                            source_port,
                            source_addr,
                            wan_ip,
                            inbound_packet_count,
                            outbound_packet_count,
                            &packet,
                        )
                    })
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
        wan_ip: Ipv4Addr,
        inbound_packet_count: &mut usize,
        outbound_packet_count: &mut usize,
        packet: &[u8],
    ) -> Option<u16> {
        let counter = if packet[30..34] == u32::from(wan_ip).to_be_bytes() {
            inbound_packet_count
        } else {
            outbound_packet_count
        };
        (*counter) += 1;

        if packet[30..34] == u32::from(wan_ip).to_be_bytes()
            && packet[36..38] == self.port.to_be_bytes()
        {
            let offset_ip = ((packet[14]) & 0x0F) as usize;
            let offset = ((packet[46] as usize) & 0xF0).overflowing_shr(4).0;
            let offset = 14 + offset_ip * 4 + offset * 4;

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

            (packet[26..30] == u32::from(wan_ip).to_be_bytes()
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
        wan_ip: Ipv4Addr,
        inbound_packet_count: &mut usize,
        outbound_packet_count: &mut usize,
        packet: &[u8],
    ) -> Option<u16> {
        if packet[30..34] == u32::from(wan_ip).to_be_bytes()
            && packet[36..38] == self.port.to_be_bytes()
        {
            let offset_ip = ((packet[14]) & 0x0F) as usize;
            let offset = 14 + offset_ip * 4;

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

            (packet[26..30] == u32::from(wan_ip).to_be_bytes()
                && packet[34..36] == self.port.to_be_bytes()
                && packet[30..34] == u32::from(*source_addr).to_be_bytes()
                && packet[36..38] == source_port.to_be_bytes())
            .then(|| *source_port)
        }
    }

    fn make_connection(&self, container: &DownloadContainer) -> anyhow::Result<u16> {
        let ImmediateTcpdumpCheck {
            port,
            protocol,
            connection_test,
            ..
        } = self;

        container
            .run(|| match protocol {
                TcpdumpProtocol::Tcp => {
                    let mut sock = TcpStream::connect((container.wan_ip(), *port))?;
                    _ = sock.write(connection_test)?;
                    Ok(sock.local_addr()?.port())
                }
                TcpdumpProtocol::Udp => {
                    let sock = UdpSocket::bind("0.0.0.0:0")?;
                    sock.send_to(&connection_test, (container.wan_ip(), *port))?;
                    Ok(sock.local_addr()?.port())
                }
            })
            .flatten()
    }

    async fn run_check(&self) -> anyhow::Result<CheckResult> {
        let container = DownloadContainer::new(None, None)
            .context("Could not create download container for immediate tcpdump check")?;

        use nix::unistd::{ForkResult, fork};

        // Semaphores are nasty but one of the simplest ways to communicate across
        // processes. We have to wait for the process to finish initializing, hence
        // shared memory and a shared semaphore
        use libc::sem_t;

        struct Sync {
            semaphore: sem_t,
            err: Result<u16, ()>,
        }

        const SYNC_SIZE: usize = std::mem::size_of::<Sync>();

        let (child, mut capture, sync) = unsafe {
            let sync: *mut Sync = libc::mmap(
                std::ptr::null_mut(),
                SYNC_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                0,
                0,
            ) as *mut _;
            let semaphore = &mut (*sync).semaphore as *mut _;

            libc::sem_init(semaphore, 1, 0);

            match fork()? {
                ForkResult::Parent { child } => {
                    let capture = self.setup_check_watch(
                        container.wan_ip(),
                        &format!("{}.0", container.name()),
                    )?;

                    libc::sem_post(semaphore);

                    (child, capture, sync)
                }
                ForkResult::Child => {
                    libc::sem_wait(semaphore);
                    libc::sem_destroy(semaphore);

                    (*sync).err = self
                        .make_connection(&container)
                        .inspect_err(|e| {
                            eprintln!("Could not make connection from download container: {e:?}");
                        })
                        .map_err(|_| {});

                    // The container will be cleaned by the parent process
                    // Without this call, the child process will attempt to
                    // delete external resources like nftables chains as
                    // the drop function is called - bad!
                    // This is why it is part of an unsafe block
                    std::mem::forget(container);
                    std::process::exit(0);
                }
            }
        };

        let mut source_port = None;
        let mut source_addr = None;
        let mut inbound_packet_count = 0;
        let mut outbound_packet_count = 0;

        use tokio::time;

        let guess_source_port = time::timeout(
            time::Duration::from_secs(4),
            self.run_check_watch(
                &mut source_port,
                &mut source_addr,
                container.wan_ip(),
                &mut inbound_packet_count,
                &mut outbound_packet_count,
                &mut capture,
            ),
        )
        .await;

        if let Err(e) = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL) {
            eprintln!("Could not kill child performing connection: {e:?}");
        }
        if let Err(e) = nix::sys::wait::waitpid(child, None) {
            eprintln!("Could not wait for child: {e:?}");
        }

        let actual_source_port = unsafe {
            (*sync).err.map_err(|_| {
                anyhow::anyhow!("Could not perform net connection and specify source port")
            })
        };

        unsafe {
            libc::munmap(sync as *mut _, SYNC_SIZE);
        }

        use serde_json::json;

        match (guess_source_port, actual_source_port) {
            (Ok(Ok(gsp)), Ok(asp)) if gsp == asp => Ok(CheckResult::succeed(
                "Successfully verified connection to service",
                json!({
                    "inbound_packet_count": inbound_packet_count,
                    "outbound_packet_count": outbound_packet_count,
                }),
            )),
            // Just in case it matched the wrong connection somehow
            // By proving that both source ports are the same, it is possible to
            // verify that the connection made and the connection analyzed were
            // the same without storing all the packets
            (Ok(Ok(_)), Ok(_)) => Box::pin(self.run_check()).await,
            (Ok(Ok(_)), Err(e)) => Ok(CheckResult::succeed(
                "Successfully sent packets out and received a result, but encountered an error when checking the source port",
                json!({
                    "inbound_packet_count": inbound_packet_count,
                    "outbound_packet_count": outbound_packet_count,
                    "system_error": format!("{e:?}"),
                }),
            )),
            (Ok(Err(e)), _) => Ok(CheckResult::fail(
                "System error when performing a tcpdump check",
                json!({
                    "inbound_packet_count": inbound_packet_count,
                    "outbound_packet_count": outbound_packet_count,
                    "system_error": format!("{e:?}")
                }),
            )),
            (Err(_), _) => Ok(CheckResult::fail(
                "Timeout when performing tcpdump check",
                json!({
                    "inbound_packet_count": inbound_packet_count,
                    "outbound_packet_count": outbound_packet_count,
                }),
            )), // (_, _, _) => todo!(),
        }
    }
}

impl<'a> CheckStep<'a> for ImmediateTcpdumpCheck {
    fn name(&self) -> &'static str {
        "Check tcpdump to verify the firewall is working"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if !self.should_run {
            return Ok(CheckResult::not_run(
                "Cannot check tcpdump when packets do not return to system via NAT reflection"
                    .to_string(),
                serde_json::json!(null),
            ));
        }

        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Could not create async environment for tcpdump check")?
            .block_on(self.run_check())
            .into_check_result("Unknown error when performing tcpdump check"))
    }
}

/// A check that tries to see if packets are able to leave and come back. Only works for checks
/// where NAT reflection is being used, to allow traffic to leave and go to a specific IP but have
/// the server reflect the traffic back to the local system. Can be considered a much more advanced
/// version of the TcpConnectCheck
///
/// It takes an address and port combination to try and make a connection to, and sends
/// data to the port over a specified protocol. The data is critical to get UDP based
/// protocols such as DNS to respond
pub fn immediate_tcpdump_check<'a>(
    port: u16,
    protocol: TcpdumpProtocol,
    connection_test: Vec<u8>,
    should_run: bool,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(ImmediateTcpdumpCheck {
        port,
        protocol,
        connection_test,
        should_run,
    })
}

#[doc(hidden)]
pub struct PassiveTcpdumpCheck {
    port: u16,
    run: bool,
    promisc: bool,
    log_func: fn(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) -> serde_json::Value,
}

impl PassiveTcpdumpCheck {
    fn make_capture(&self) -> anyhow::Result<pcap::Capture<pcap::Active>> {
        let device = pcap::Device::lookup()
            .context("Could not get default PCAP capture device")?
            .ok_or(anyhow::anyhow!("Could not find pcap device"))?;

        let capture = pcap::Capture::from_device(device)
            .context("Could not load packet capture device for passive tcpdump check")?
            .promisc(self.promisc)
            .immediate_mode(true)
            .timeout(10);

        let mut capture = capture
            .open()
            .context("Could not open packet capture device for passive tcpdump check")?;

        capture
            .filter(&format!("port {}", self.port), false)
            .context("Could not set filter for passive tcpdump check")?;

        Ok(capture)
    }

    fn get_first_packet(
        &self,
        capture: &mut pcap::Capture<pcap::Active>,
    ) -> anyhow::Result<(
        Ipv4Addr,
        u16,
        chrono::DateTime<chrono::Utc>,
        TcpdumpProtocol,
    )> {
        loop {
            let p = capture
                .next_packet()
                .context("Could not acquire the next packet")?;

            if p.data.len() < 40 {
                continue;
            }

            if u16::from_be_bytes([p[12], p[13]]) != 0x800 {
                // ignore non ipv4 traffic, it isn't real
                continue;
            }

            let ip_packet = &p.data[14..];
            let ihl = (ip_packet[0] & 0x0F) as usize;

            let Some(protocol) = TcpdumpProtocol::from_int(ip_packet[9]) else {
                continue;
            };

            let l4_packet = &ip_packet[ihl * 4..];

            let src_ip =
                Ipv4Addr::from_octets([ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]]);
            let src_port = u16::from_be_bytes([l4_packet[0], l4_packet[1]]);
            let dst_port = u16::from_be_bytes([l4_packet[2], l4_packet[3]]);

            if dst_port != self.port {
                continue;
            }

            return Ok((src_ip, src_port, chrono::Utc::now(), protocol));
        }
    }

    async fn get_response_packet(
        &self,
        capture: pcap::Capture<pcap::Active>,
        source_ip: Ipv4Addr,
        source_port: u16,
        proto: TcpdumpProtocol,
    ) -> anyhow::Result<()> {
        let mut stream = capture.setnonblock()?.stream(TcpdumpCodec)?;
        while let Some(p) = stream.next().await {
            let p = p?.1;

            if p.len() < 40 {
                continue;
            }

            if u16::from_be_bytes([p[12], p[13]]) != 0x800 {
                // ignore non ipv4 traffic, it isn't real
                continue;
            }

            let ip_packet = &p[14..];
            let ihl = (ip_packet[0] & 0x0F) as usize;

            if Some(proto) != TcpdumpProtocol::from_int(ip_packet[9]) {
                continue;
            }

            let l4_packet = &ip_packet[ihl * 4..];

            let dst_ip =
                Ipv4Addr::from_octets([ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]]);
            let src_port = u16::from_be_bytes([l4_packet[0], l4_packet[1]]);
            let dst_port = u16::from_be_bytes([l4_packet[2], l4_packet[3]]);

            if src_port != self.port || dst_ip != source_ip || dst_port != source_port {
                continue;
            }

            return Ok(());
        }

        anyhow::bail!("Tcpdump stream ran out of packets")
    }

    fn get_debug_route(&self, source_ip: Ipv4Addr) -> serde_json::Value {
        let bb = match Busybox::new() {
            Ok(bb) => bb,
            Err(e) => return format!("Could not load busybox: {e:?}").into(),
        };

        match bb.execute(&["ip", "route", "get", &format!("{source_ip}")]) {
            Ok(s) => s.trim().into(),
            Err(e) => format!("Could not print route: {e:?}").into(),
        }
    }
}

impl<'a> CheckStep<'a> for PassiveTcpdumpCheck {
    fn name(&self) -> &'static str {
        "Wait for an inbound connection on port and verify that return packets are sent"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if !self.run {
            return Ok(CheckResult::not_run(
                "Check was not specified as required for troubleshooting",
                serde_json::json!(null),
            ));
        }

        let mut capture = self.make_capture()?;
        let (source_ip, source_port, start, proto) = self.get_first_packet(&mut capture)?;

        use tokio::{
            runtime::Builder,
            time::{Duration, timeout},
        };
        let result = Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                timeout(
                    Duration::from_secs(5),
                    self.get_response_packet(capture, source_ip, source_port, proto),
                )
                .await
            });

        let end = chrono::Utc::now();

        let route = self.get_debug_route(source_ip);
        let logs = (self.log_func)(start, end);

        Ok(match result {
            Ok(Ok(())) => CheckResult::succeed(
                "System successfully responded to traffic",
                serde_json::json!({
                    "debug_route": route,
                    "system_logs": logs
                }),
            ),
            Ok(Err(e)) => CheckResult::fail(
                "System error occurred when attempting to do a passive tcpdump check",
                serde_json::json!({
                    "debug_route": route,
                    "system_logs": logs,
                    "sytem_error": format!("{e:?}"),
                }),
            ),
            Err(_) => CheckResult::fail(
                "System did not respond in an appropriate amount of time when doing a tcpdump check",
                serde_json::json!({
                    "debug_route": route,
                    "system_logs": logs,
                }),
            ),
        })
    }
}

/// Listen for an inbound connection on the specified port, and verify that a
/// response is provided by the operating system.
///
/// Run is provided as an argument to allow avoiding the use of [`filter_check`],
/// building that functionality into this check as it is an expensive check
/// (time-wise)
///
/// Promisc allows specifying if this check should listen for traffic going to
/// other servers
pub fn passive_tcpdump_check<'a>(
    port: u16,
    run: bool,
    promisc: bool,
    log_func: fn(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) -> serde_json::Value,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(PassiveTcpdumpCheck {
        port,
        run,
        promisc,
        log_func,
    })
}
