use clap::Parser;

use crate::utils::ports::{self, TcpStates};

/// Enumerate open ports and services on the system
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Ports;

impl super::Command for Ports {
    fn execute(self) -> anyhow::Result<()> {
        let tcp_ports = ports::parse_net_tcp()?;

        println!(
            "{:>10}:{:<10} {:>12}: {} {}",
            "Local addr", "Local port", "PID", "Command line", "(Cgroup)"
        );

        for port in tcp_ports {
            if port.state != TcpStates::LISTEN {
                continue;
            }

            let pid = port
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or("unknown".to_string());
            let cmdline = port.cmdline.clone().unwrap_or_default();
            let cgroup = port
                .cgroup
                .map(|cg| format!("({})", cg))
                .unwrap_or_default();

            println!(
                "{:>10}:{:<10} {:>12}: {} {}",
                port.local_address, port.local_port, pid, cmdline, cgroup
            );
        }

        Ok(())
    }
}
