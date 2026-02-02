use std::net::Ipv4Addr;

use chrono::Utc;

use super::*;

/// Troubleshoot a DNS server connection
#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Dns {
    /// The host to query (the domain name)
    #[arg(long, short = 'd', default_value = "google.com")]
    domain: String,

    /// The DNS server to query
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    host: Ipv4Addr,

    /// The port of the DNS server
    #[arg(long, short, default_value_t = 53)]
    port: u16,

    /// The query type (A, AAAA, MX, etc.)
    #[arg(long, short = 't', default_value = "A")]
    qtype: String,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    local: bool,

    /// Listen for an external connection attempt, and diagnose what appears to
    /// be going wrong with such a check. All other steps attempt to initiate connections
    #[arg(long, short)]
    external: bool,
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
        }
    }
}



#[cfg(unix)]
impl Troubleshooter for Dns {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {

        Ok(vec![
            filter_check(
                systemd_services_check(vec![
                    "named",
                    "bind9",
                    "systemd-resolved",
                    "unbound",
                    "dnsmasq",
                ]),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            filter_check(
                openrc_services_check(vec!["named", "bind9", "unbound", "dnsmasq"]),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            binary_ports_check(
                ["named", "bind9", "systemd-resolved", "unbound", "dnsmasq"],
                self.port,
                CheckIpProtocol::Udp,
                self.host.is_loopback() || self.local,
            ),
            binary_ports_check(
                ["named", "bind9", "systemd-resolved", "unbound", "dnsmasq"],
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            check_fn("DNS Query", |tr| self.try_dns_query(tr)),
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

#[cfg(windows)]
impl Troubleshooter for Dns {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![check_fn("DNS Query", |tr| self.try_dns_query(tr))])
    }

    fn is_local(&self) -> bool {
        self.host.is_loopback() || self.local
    }
}

impl Dns {
    fn try_dns_query(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let host = self.host;
        let port = self.port;
        let domain = &self.domain;
        let qtype = &self.qtype;

        let start = Utc::now();

        // Try using nslookup as it is very common
        let cmd = format!(
            "nslookup -port={} -q={} {} {}",
            port, qtype, domain, host
        );
        let res = crate::utils::qx(&cmd);

        let end = Utc::now();

        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        match res {
            Ok((status, output)) if status.success() => {
                if output.to_lowercase().contains("can't find") || output.contains("NXDOMAIN") {
                    Ok(CheckResult::fail(
                        format!("DNS query for {} failed (record not found)", domain),
                        serde_json::json!({
                            "command": cmd,
                            "output": output,
                            "system_logs": logs,
                        }),
                    ))
                } else {
                    Ok(CheckResult::succeed(
                        format!("DNS query for {} succeeded", domain),
                        serde_json::json!({
                            "command": cmd,
                            "output": output,
                            "system_logs": logs,
                        }),
                    ))
                }
            }
            Ok((status, output)) => Ok(CheckResult::fail(
                format!("DNS query for {} failed", domain),
                serde_json::json!({
                    "command": cmd,
                    "exit_code": status.code(),
                    "output": output,
                    "system_logs": logs,
                }),
            )),
            Err(e) => Ok(CheckResult::fail(
                "Could not run DNS query command",
                serde_json::json!({
                    "command": cmd,
                    "error": format!("{e:?}"),
                    "system_logs": logs,
                }),
            )),
        }
    }
}
