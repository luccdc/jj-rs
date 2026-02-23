use crate::utils::{clap::Host, os_version::get_distro};
use chrono::Utc;
use curl::easy::Easy;
use eyre::Context;
use std::io::{Write, stdout};
use std::net::Ipv4Addr;

use super::*;

#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Pop3Troubleshooter {
    /// The host to connect to and attempt signing in
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    host: Host,

    /// The port of the POP3 server
    #[arg(long, short, default_value_t = 110)]
    port: u16,

    /// The user to sign in as
    #[arg(long, short, default_value = "root")]
    user: String,

    /// [`CheckValue`] The password to authenticate with
    #[arg(long, short = 'P', default_value_t = Default::default())]
    password: CheckValue,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    local: bool,

    /// Listen for an external connection attempt, and diagnose what appears to
    /// be going wrong with such a check. All other steps attempt to initiate connections
    #[arg(long, short)]
    external: bool,

    /// Disable the download shell used to test the POP3 and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,
}

impl Default for Pop3Troubleshooter {
    fn default() -> Self {
        Pop3Troubleshooter {
            host: Host::from("127.0.0.1".to_string()),
            port: 25,
            user: "root".to_string(),
            password: CheckValue::stdin(),
            local: false,
            external: false,
            disable_download_shell: false,
            sneaky_ip: None,
        }
    }
}

impl Troubleshooter for Pop3Troubleshooter {
    fn display_name(&self) -> &'static str {
        "Pop3"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        let _distro = get_distro().context("could not load distribution for POP3 check")?;

        Ok(vec![
            #[cfg(unix)]
            filter_check(
                systemd_services_check(["dovecot"]),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            #[cfg(unix)]
            filter_check(
                openrc_services_check(["dovecot"]),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            #[cfg(unix)]
            binary_ports_check(
                Some(["dovecot"]),
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            tcp_connect_check_dns(
                self.host.clone(),
                self.port,
                self.disable_download_shell,
                self.sneaky_ip,
            )?,
            #[cfg(unix)]
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"".to_vec(), // Irrelevant for tcp.
                self.host.is_loopback() || self.local,
            ),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
            #[cfg(unix)]
            passive_tcpdump_check(
                self.port,
                self.external,
                !self.host.is_loopback() && !self.local,
                get_system_logs,
            ),
        ])
    }
}

impl Pop3Troubleshooter {
    pub fn try_remote_login(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let host = self.host.clone();
        let port = self.port;
        let user = self.user.clone();
        let pass = self
            .password
            .clone()
            .resolve_prompt(tr, "POP3 Password: ")?;

        std::thread::sleep(std::time::Duration::from_secs(1));
        let start = Utc::now();

        let mut easy = Easy::new();

        let check_result = CheckResult::succeed(
            format!("Connected!"),
            serde_json::json!({
                "test": "fine",
            }),
        );

        easy.username(user.as_str());
        easy.password(pass.as_str());

        easy.url(format!("pop3://{host}:{port}").as_str());

        easy.write_function(|data| {
            stdout().write_all(data).unwrap();
            Ok(data.len())
        })
        .unwrap();
        easy.perform().unwrap();

        let end = Utc::now();

        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        Ok(check_result.merge_overwrite_details(serde_json::json!({
            "system_logs": logs,
        })))
    }
}
