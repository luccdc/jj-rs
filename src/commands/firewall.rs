use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Write, stdout},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::Stdio,
};

use clap::{Parser, Subcommand};

use crate::utils::{
    busybox::Busybox,
    logs::ellipsize,
    nft::Nft,
    ports::linux::{SocketState, parse_net_tcp, parse_net_udp},
};

#[derive(Subcommand, Debug)]
enum FirewallCmd {
    /// Generate an NFT configuration file based on the current open ports
    #[command(visible_alias = "qs")]
    QuickSetup(QuickSetup),

    /// Configure the firewall with NFT to perform NAT redirection from one
    /// IP to another
    #[command(visible_alias = "nr")]
    NatRedirect(NatRedirect),
}

/// Firewall management
#[derive(Parser, Debug)]
#[command(about, version)]
pub struct Firewall {
    #[command(subcommand)]
    cmd: FirewallCmd,
}

impl super::Command for Firewall {
    fn execute(self) -> eyre::Result<()> {
        match self.cmd {
            FirewallCmd::QuickSetup(qs) => qs.execute(),
            FirewallCmd::NatRedirect(nr) => nr.execute(),
        }
    }
}

#[derive(Parser, Debug)]
struct QuickSetup {
    /// Specify an ELK IP to allow downloading resources from and uploading logs to. Allows ports 5044, 5601, and 8080 to the ELK IP
    #[arg(short, long)]
    elk_ip: Option<Ipv4Addr>,

    /// Where to save the resulting firewall configuration. Leave unconfigured or use `-` to print to standard out
    #[arg(short = 'f', long)]
    output_file: Option<PathBuf>,

    /// Add firewall rules to allow currently established connections. Useful for web servers connecting to a central database
    #[arg(short, long)]
    allow_established_connections: bool,

    /// Add firewall rules to allow outbound DNS, HTTP, and HTTPS
    #[arg(short = 'o', long)]
    allow_outbound: bool,

    /// Flush ruleset instead of just the `core_firewall` table.
    #[arg(short = 'F', long)]
    flush_ruleset: bool,
}

impl QuickSetup {
    fn execute(self) -> eyre::Result<()> {
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

        let tcp_sockets = parse_net_tcp()?;
        let tcp_listen_ports = tcp_sockets
            .iter()
            .filter(|p| p.state == SocketState::LISTEN)
            .map(|p| (p.local_port, p))
            .collect::<BTreeMap<_, _>>();

        let estab_tcp_listen_ports = tcp_sockets
            .iter()
            .filter(|p| p.state == SocketState::ESTABLISHED)
            .map(|p| {
                (
                    (
                        p.local_port,
                        p.remote_port,
                        p.local_address,
                        p.remote_address,
                    ),
                    p,
                )
            })
            .collect::<BTreeMap<_, _>>();

        // shows as UNCONN in `ss`
        // https://github.com/iproute2/iproute2/blob/ca756f36a0c6d24ab60657f8d14312c17443e5f0/misc/ss.c#L1413
        let udp_listen_ports = parse_net_udp()?
            .into_iter()
            .filter(|p| p.state == SocketState::CLOSE)
            .map(|p| (p.local_port, p))
            .collect::<BTreeMap<_, _>>();

        if self.flush_ruleset {
            writeln!(ob, "flush ruleset\n")?;
        } else {
            writeln!(ob, "table inet core_firewall")?;
            writeln!(ob, "flush table inet core_firewall\n")?;
            writeln!(ob, "delete table inet core_firewall\n")?;
        }

        writeln!(ob, "table inet core_firewall {{")?;
        writeln!(ob, "    chain input {{")?;
        writeln!(ob, "        type filter hook input priority 0; policy drop")?;
        writeln!(ob, "        iifname lo accept\n")?;

        writeln!(ob, "        #### TCP ####")?;
        for (local_port, port) in tcp_listen_ports {
            writeln!(
                ob,
                "        tcp dport {:<5} ct state new accept   # {}",
                local_port,
                ellipsize(37, &port.cmdline.clone().unwrap_or(String::new()))
            )?;
        }
        writeln!(ob)?;

        writeln!(ob, "        #### UDP ####")?;
        for (local_port, port) in udp_listen_ports {
            writeln!(
                ob,
                "        udp dport {:<5} ct state new accept # {}",
                local_port,
                ellipsize(37, &port.cmdline.clone().unwrap_or(String::new()))
            )?;
        }
        writeln!(ob)?;

        writeln!(
            ob,
            "        icmp type {{ echo-request, echo-reply }} ct state new accept"
        )?;
        writeln!(ob, "        ct state established,related accept")?;
        writeln!(ob, r#"        log prefix "inbound-drop: " drop"#)?;
        writeln!(ob, "    }}\n")?;
        writeln!(ob, "    chain output {{")?;
        writeln!(
            ob,
            "        type filter hook output priority 0; policy drop"
        )?;
        writeln!(ob, "        oifname lo accept")?;

        if self.allow_established_connections {
            writeln!(ob, "\n        #### ESTABLISHED ####")?;
            for conn in estab_tcp_listen_ports.values() {
                writeln!(
                    ob,
                    "        ip daddr {} tcp dport {} ct state new accept # {}",
                    conn.remote_address,
                    conn.remote_port,
                    ellipsize(22, &conn.cmdline.clone().unwrap_or(String::new()))
                )?;
            }
            writeln!(ob)?;
        }

        if let Some(elk_ip) = self.elk_ip {
            writeln!(ob, "        #### ELK ####")?;
            writeln!(
                ob,
                "        ip daddr {elk_ip} tcp dport 5601 ct state new accept"
            )?;
            writeln!(
                ob,
                "        ip daddr {elk_ip} tcp dport 8080 ct state new accept"
            )?;
            writeln!(
                ob,
                "        ip daddr {elk_ip} tcp dport 5040 ct state new accept"
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
        writeln!(ob, r#"        log prefix "outbound-drop: " reject"#)?;
        writeln!(ob, "    }}")?;
        writeln!(ob, "}}")?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
struct NatRedirect {
    /// Specify the IP address to listen on and perform NAT for
    #[arg(short, long)]
    listen_ip: IpAddr,

    /// Specify the target IP address to send traffic to
    #[arg(short, long)]
    target_ip: IpAddr,
}

impl NatRedirect {
    fn execute(self) -> eyre::Result<()> {
        let nft = Nft::new()?;

        let NatRedirect {
            listen_ip,
            target_ip,
        } = self;

        let tbl_name = format!("nat_reflect_{listen_ip}_to_{target_ip}");

        nft.exec(format!("delete table inet {tbl_name}"), Stdio::null())?;
        nft.exec(format!("add table inet {tbl_name}"), Stdio::null())?;
        nft.exec(format!("add chain inet {tbl_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}"), Stdio::null())?;
        nft.exec(format!("add chain inet {tbl_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}"), Stdio::null())?;
        nft.exec(
            format!(
                "add rule inet {tbl_name} prerouting ip daddr {listen_ip} dnat ip to {target_ip}"
            ),
            Stdio::null(),
        )?;
        nft.exec(
            format!("add rule inet {tbl_name} postrouting ip daddr {target_ip} masquerade"),
            Stdio::null(),
        )?;

        std::fs::write("/proc/sys/net/ipv4/conf/all/proxy_arp", "1")?;

        let bb = Busybox::new()?;

        bb.execute(&[
            "ip",
            "route",
            "add",
            &format!("{listen_ip}/32"),
            "dev",
            "lo",
        ])?;

        println!("Added NAT reflection from {listen_ip} to {target_ip}");

        Ok(())
    }
}
