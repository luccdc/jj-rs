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
struct AnyServiceCheckStep<'a> {
    name: &'static str,
    checks: Vec<Box<dyn CheckStep<'a> + 'a>>,
}

#[cfg(unix)]
impl<'a> CheckStep<'a> for AnyServiceCheckStep<'a> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let mut failed_logs = Vec::new();
        let mut not_run_logs = Vec::new();

        for check in &self.checks {
            let res = check.run_check(tr)?;
            match res.result_type {
                CheckResultType::Success => return Ok(res),
                CheckResultType::Failure => failed_logs.push(format!("{}: {}", check.name(), res.log_item)),
                CheckResultType::NotRun => not_run_logs.push(format!("{}: {}", check.name(), res.log_item)),
            }
        }

        if failed_logs.is_empty() {
             Ok(CheckResult::not_run(
                "No supported DNS service installed/checkable",
                serde_json::json!({
                    "reasons": not_run_logs
                })
            ))
        } else {
             Ok(CheckResult::fail(
                "No supported DNS service found active",
                serde_json::json!({
                    "failures": failed_logs,
                    "not_run": not_run_logs
                })
            ))
        }
    }
}

#[cfg(unix)]
fn any_check<'a>(
    name: &'static str,
    checks: Vec<Box<dyn CheckStep<'a> + 'a>>,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(AnyServiceCheckStep { name, checks })
}

#[cfg(unix)]
struct NamedServiceCheckStep<'a> {
    name: &'static str,
    service_name: String,
    inner: Box<dyn CheckStep<'a> + 'a>,
}

#[cfg(unix)]
impl<'a> CheckStep<'a> for NamedServiceCheckStep<'a> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let mut res = self.inner.run_check(tr)?;
        res.log_item = format!("{} ({})", res.log_item, self.service_name);
        Ok(res)
    }
}

#[cfg(unix)]
fn named_check<'a>(
    name: &'static str,
    service: &str,
    inner: Box<dyn CheckStep<'a> + 'a>,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(NamedServiceCheckStep {
        name,
        service_name: service.to_string(),
        inner,
    })
}

#[cfg(unix)]
impl Troubleshooter for Dns {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {

        Ok(vec![
            filter_check(
                any_check(
                    "Check for any DNS service",
                    vec![
                        named_check(
                            "Check named service",
                            "named",
                            systemd_service_check("named"),
                        ),
                        named_check(
                            "Check bind9 service",
                            "bind9",
                            systemd_service_check("bind9"),
                        ),
                        named_check(
                            "Check systemd-resolved service",
                            "systemd-resolved",
                            systemd_service_check("systemd-resolved"),
                        ),
                        named_check(
                            "Check unbound service",
                            "unbound",
                            systemd_service_check("unbound"),
                        ),
                        named_check(
                            "Check dnsmasq service",
                            "dnsmasq",
                            systemd_service_check("dnsmasq"),
                        ),
                        named_check(
                            "Check named service (openrc)",
                            "named",
                            openrc_service_check("named"),
                        ),
                        named_check(
                            "Check bind9 service (openrc)",
                            "bind9",
                            openrc_service_check("bind9"),
                        ),
                        named_check(
                            "Check unbound service (openrc)",
                            "unbound",
                            openrc_service_check("unbound"),
                        ),
                        named_check(
                            "Check dnsmasq service (openrc)",
                            "dnsmasq",
                            openrc_service_check("dnsmasq"),
                        ),
                    ]
                ),
                self.host.is_loopback() || self.local,
                "Cannot check systemd/openrc service on remote host",
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
