use std::{
    io::Write,
    net::{Ipv4Addr, TcpStream, UdpSocket},
};

use anyhow::Context;
use futures_util::StreamExt;

use crate::utils::{
    checks::{CheckResult, CheckStep, IntoCheckResult, TroubleshooterRunner},
    download_container::DownloadContainer,
};

use super::{CheckIpProtocol, TcpdumpCodec};

struct ImmediateTcpdumpCheck {
    port: u16,
    protocol: CheckIpProtocol,
    connection_test: Vec<u8>,
    should_run: bool,
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
                        CheckIpProtocol::Tcp => {
                            "tcp"
                        }
                        CheckIpProtocol::Udp => {
                            "udp"
                        }
                    },
                    self.port
                ),
                false,
            )
            .context("Could not set filter for tcpdump check")?;

        capture
            .stream(TcpdumpCodec)
            .context("Could not convert capture device to stream for tcpdump check")
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
                CheckIpProtocol::Udp => (header.caplen >= 38)
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
                CheckIpProtocol::Tcp => (header.caplen >= 48)
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

            if packet[offset..] == self.connection_test {
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
            .then_some(*source_port)
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
            let offset = 14 + offset_ip * 4;

            if packet.len() - offset < self.connection_test.len() {
                None?;
            }

            if packet[offset..] == self.connection_test {
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
            .then_some(*source_port)
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
                CheckIpProtocol::Tcp => {
                    let mut sock = TcpStream::connect((container.wan_ip(), *port))?;
                    _ = sock.write(connection_test)?;
                    Ok(sock.local_addr()?.port())
                }
                CheckIpProtocol::Udp => {
                    let sock = UdpSocket::bind("0.0.0.0:0")?;
                    sock.send_to(connection_test, (container.wan_ip(), *port))?;
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
        "Verify firewall with tcpdump"
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
///
/// Example:
/// ```
/// # use jj_rs::utils::checks::{CheckIpProtocol, immediate_tcpdump_check};
/// immediate_tcpdump_check(
///     22,
///     CheckIpProtocol::Tcp,
///     b"opensh".to_vec(),
///     true
/// );
/// ```
pub fn immediate_tcpdump_check<'a>(
    port: u16,
    protocol: CheckIpProtocol,
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
