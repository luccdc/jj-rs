use clap::Parser;

use crate::utils::ports::{self, SocketState};

/// Enumerate open ports and services on the system
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Ports;

impl super::Command for Ports {
    fn execute(self) -> eyre::Result<()> {
        let tcp_ports = ports::parse_net_tcp()?;

        println!(
            "{:>10}:{:<10} {:>12}: Command line (Cgroup)",
            "Local addr", "Local port", "PID"
        );

        for port in tcp_ports {
            if port.state != SocketState::LISTEN {
                continue;
            }

            let pid = port
                .pid
                .map_or("unknown".to_string(), |pid| pid.to_string());
            let cmdline = port.cmdline.clone().unwrap_or_default();
            let cgroup = port.cgroup.map(|cg| format!("({cg})")).unwrap_or_default();

            println!(
                "{:>10}:{:<10} {:>12}: {} {}",
                port.local_address, port.local_port, pid, cmdline, cgroup
            );
        }

        Ok(())
    }
}
