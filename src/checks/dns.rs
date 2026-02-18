use std::net::Ipv4Addr;

use chrono::Utc;

use super::*;

/// Troubleshoot a DNS server connection
#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Dns {
    /// The host to query (the domain name)
    #[arg(long, short = 'd', default_value = "google.com")]
    pub domain: String,

    /// The DNS server to query
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    pub host: Ipv4Addr,

    /// The port of the DNS server
    #[arg(long, short, default_value_t = 53)]
    pub port: u16,

    /// The query type (A, AAAA, MX, etc.)
    #[arg(long, short = 't', default_value = "A")]
    pub qtype: String,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    pub local: bool,

    /// Listen for an external connection attempt, and diagnose what appears to
    /// be going wrong with such a check. All other steps attempt to initiate connections
    #[arg(long, short)]
    pub external: bool,

    /// Disable the download shell used to test the HTTP and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            domain: "google.com".to_string(),
            host: Ipv4Addr::from(0x7F_00_00_01),
            port: 53,
            qtype: "A".to_string(),
            local: false,
            external: false,
            disable_download_shell: false,
            sneaky_ip: None,
        }
    }
}

impl Troubleshooter for Dns {
    fn display_name(&self) -> &'static str {
        "DNS"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![
            filter_check(
                service_check(
                    #[cfg(unix)]
                    ["named", "bind9", "unbound", "dnsmasq"],
                    #[cfg(windows)]
                    ["DNS"],
                ),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            binary_ports_check(
                #[cfg(unix)]
                Some(["named", "bind9", "unbound", "dnsmasq"]),
                #[cfg(windows)]
                Some(["dns.exe"]),
                self.port,
                CheckIpProtocol::Udp,
                self.host.is_loopback() || self.local,
            ),
            #[cfg(unix)]
            binary_ports_check(
                #[cfg(unix)]
                Some(["named", "bind9", "unbound", "dnsmasq"]),
                #[cfg(windows)]
                Some(["dns.exe"]),
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            check_fn("DNS Query", |tr| Ok(self.try_dns_query(tr))),
            #[cfg(unix)]
            passive_tcpdump_check(
                self.port,
                self.external,
                !self.host.is_loopback() && !self.local,
                get_system_logs,
            ),
        ])
    }

    fn is_local(&self) -> bool {
        self.host.is_loopback() || self.local
    }
}

impl Dns {
    fn try_dns_query(&self, _tr: &mut dyn TroubleshooterRunner) -> CheckResult {
        let host = self.host;
        let port = self.port;
        let domain = &self.domain;
        let qtype = &self.qtype;

        // Try using nslookup as it is very common
        let cmd = format!("nslookup -port={port} -q={qtype} {domain} {host}");

        let (res, start) = crate::utils::checks::optionally_run_in_container(
            host.is_loopback() || self.local,
            self.disable_download_shell,
            self.sneaky_ip,
            || crate::utils::qx(&cmd),
        );

        let end = Utc::now();

        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        match res {
            Ok((status, output)) if status.success() => {
                if output.to_lowercase().contains("can't find") || output.contains("NXDOMAIN") {
                    CheckResult::fail(
                        format!("DNS query for {domain} failed (record not found)"),
                        serde_json::json!({
                            "command": cmd,
                            "output": output,
                            "system_logs": logs,
                        }),
                    )
                } else {
                    CheckResult::succeed(
                        format!("DNS query for {domain} succeeded"),
                        serde_json::json!({
                            "command": cmd,
                            "output": output,
                            "system_logs": logs,
                        }),
                    )
                }
            }
            Ok((status, output)) => CheckResult::fail(
                format!("DNS query for {domain} failed"),
                serde_json::json!({
                    "command": cmd,
                    "exit_code": status.code(),
                    "output": output,
                    "system_logs": logs,
                }),
            ),
            Err(e) => CheckResult::fail(
                "Could not run DNS query command",
                serde_json::json!({
                    "command": cmd,
                    "error": format!("{e:?}"),
                    "system_logs": logs,
                }),
            ),
        }
    }
}
