use std::net::Ipv4Addr;

use anyhow::Context;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use pcap::{Active, Capture, Device};
use serde_json::{Value, json};

use crate::utils::{
    busybox::Busybox,
    checks::{CheckResult, CheckStep, TroubleshooterRunner, check_fns::TcpdumpCodec},
};

use super::CheckIpProtocol;

struct PassiveTcpdumpCheck {
    port: u16,
    run: bool,
    promisc: bool,
    log_func: fn(DateTime<Utc>, DateTime<Utc>) -> Value,
}

impl PassiveTcpdumpCheck {
    fn make_capture(&self) -> anyhow::Result<Capture<Active>> {
        let device = Device::lookup()
            .context("Could not get default PCAP capture device")?
            .ok_or(anyhow::anyhow!("Could not find pcap device"))?;

        let capture = Capture::from_device(device)
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
        capture: &mut Capture<Active>,
    ) -> anyhow::Result<(Ipv4Addr, u16, DateTime<Utc>, CheckIpProtocol)> {
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

            let Some(protocol) = CheckIpProtocol::from_int(ip_packet[9]) else {
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

            return Ok((src_ip, src_port, Utc::now(), protocol));
        }
    }

    async fn get_response_packet(
        &self,
        capture: pcap::Capture<pcap::Active>,
        source_ip: Ipv4Addr,
        source_port: u16,
        proto: CheckIpProtocol,
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

            if Some(proto) != CheckIpProtocol::from_int(ip_packet[9]) {
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

    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> anyhow::Result<CheckResult> {
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

        let end = Utc::now();

        let route = self.get_debug_route(source_ip);
        let logs = (self.log_func)(start, end);

        Ok(match result {
            Ok(Ok(())) => CheckResult::succeed(
                "System successfully responded to traffic",
                json!({
                    "debug_route": route,
                    "system_logs": logs
                }),
            ),
            Ok(Err(e)) => CheckResult::fail(
                "System error occurred when attempting to do a passive tcpdump check",
                json!({
                    "debug_route": route,
                    "system_logs": logs,
                    "sytem_error": format!("{e:?}"),
                }),
            ),
            Err(_) => CheckResult::fail(
                "System did not respond in an appropriate amount of time when doing a tcpdump check",
                json!({
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
/// Run is provided as an argument to allow avoiding the use of [`super::filter_check`],
/// building that functionality into this check as it is an expensive check
/// (time-wise)
///
/// Promisc allows specifying if this check should listen for traffic going to
/// other servers
pub fn passive_tcpdump_check<'a>(
    port: u16,
    run: bool,
    promisc: bool,
    log_func: fn(DateTime<Utc>, DateTime<Utc>) -> serde_json::Value,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(PassiveTcpdumpCheck {
        port,
        run,
        promisc,
        log_func,
    })
}
