use std::{
    fs::OpenOptions,
    io::{Write, stdout},
    net::Ipv4Addr,
    path::PathBuf,
};

use clap::{Parser, Subcommand};

use crate::utils::ports::{SocketState, SocketType, parse_net_tcp_udp};

#[derive(Subcommand, Debug)]
enum FirewallCmd {
    /// Generate an NFT configuration file based on the current open ports
    #[command(visible_alias = "qs")]
    QuickSetup(QuickSetup),
}

/// Firewall management
#[derive(Parser, Debug)]
#[command(about, version)]
pub struct Firewall {
    #[command(subcommand)]
    cmd: FirewallCmd,
}

impl super::Command for Firewall {
    fn execute(self) -> anyhow::Result<()> {
        match self.cmd {
            FirewallCmd::QuickSetup(qs) => qs.execute(),
        }
    }
}

#[derive(Parser, Debug)]
struct QuickSetup {
    /// Specify an ELK IP to allow downloading resources from and uploading logs to. Allows ports 5044, 5601, and 8080 to the ELK IP
    #[arg(short, long)]
    elk_ip: Option<Ipv4Addr>,

    /// Where to save the resulting firewall configuration. Leave unconfigured or use `-` to print to standard out
    #[arg(short, long)]
    output_file: Option<PathBuf>,

    /// Add firewall rules to allow currently established connections. Useful for web servers connecting to a central database
    #[arg(short, long)]
    allow_established_connections: bool,

    /// Add firewall rules to allow outbound DNS, HTTP, and HTTPS
    #[arg(short, long)]
    allow_outbound: bool,
}

impl QuickSetup {
    fn execute(self) -> anyhow::Result<()> {
        let sockets = parse_net_tcp_udp()?;

        let mut ob: Box<dyn Write> = match self.output_file {
            None => Box::new(stdout()),
            Some(p) if *p == *"-" => Box::new(stdout()),
            Some(p) => Box::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(p)?,
            ),
        };

        let tcp_listen_ports = sockets
            .iter()
            .filter(|p| p.socket_type == SocketType::Tcp && p.state == SocketState::LISTEN)
            .collect::<Vec<_>>();
        // shows as UNCONN in `ss`
        // https://github.com/iproute2/iproute2/blob/ca756f36a0c6d24ab60657f8d14312c17443e5f0/misc/ss.c#L1413
        let udp_listen_ports = sockets
            .iter()
            .filter(|p| p.socket_type == SocketType::Udp && p.state == SocketState::CLOSE)
            .collect::<Vec<_>>();

        let estab_tcp_listen_ports = sockets
            .iter()
            .filter(|p| p.socket_type == SocketType::Tcp && p.state == SocketState::ESTABLISHED)
            .collect::<Vec<_>>();

        writeln!(ob, "flush ruleset")?;
        writeln!(ob, "table inet core_firewall {{")?;
        writeln!(ob, "    chain input {{")?;
        writeln!(ob, "        type filter hook input priority 0; policy drop")?;
        writeln!(ob, "        iifname lo accept\n")?;

        writeln!(ob, "        #### TCP ####")?;
        for port in tcp_listen_ports {
            writeln!(
                ob,
                "        tcp dport {} ct state new accept",
                port.local_port
            )?;
        }
        writeln!(ob)?;

        writeln!(ob, "        #### UDP ####")?;
        for port in udp_listen_ports {
            writeln!(
                ob,
                "        udp dport {} ct state new accept",
                port.local_port
            )?;
        }
        writeln!(ob)?;

        writeln!(ob, "        ct state established,related accept")?;
        writeln!(ob, "    }}\n")?;
        writeln!(ob, "    chain output {{")?;
        writeln!(
            ob,
            "        type filter hook output priority 0; policy drop"
        )?;
        writeln!(ob, "        oifname lo accept")?;

        if self.allow_established_connections {
            writeln!(ob, "\n        #### ESTABLISHED ####")?;
            for conn in estab_tcp_listen_ports {
                writeln!(
                    ob,
                    "        ip daddr {} tcp dport {} ct state new accept",
                    conn.remote_address, conn.remote_port
                )?;
            }
            writeln!(ob)?;
        }

        if let Some(elk_ip) = self.elk_ip {
            writeln!(ob, "        #### ELK ####")?;
            writeln!(
                ob,
                "        ip daddr {} tcp dport 5601 ct state new accept",
                elk_ip
            )?;
            writeln!(
                ob,
                "        ip daddr {} tcp dport 8080 ct state new accept",
                elk_ip
            )?;
            writeln!(
                ob,
                "        ip daddr {} tcp dport 5040 ct state new accept",
                elk_ip
            )?;
            writeln!(ob)?;
        }

        if self.allow_outbound {
            writeln!(ob, "        #### OUTBOUND HTTP ####")?;
            writeln!(ob, "        tcp dport 80 ct state new accept")?;
            writeln!(ob, "        tcp dport 443 ct state new accept")?;
            writeln!(ob, "        udp dport 53 ct state new accept")?;
            writeln!(ob)?;
        }

        writeln!(ob, "        ct state established,related accept")?;
        writeln!(ob, "    }}")?;
        writeln!(ob, "}}")?;

        Ok(())
    }
}
