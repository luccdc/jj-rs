use std::{net::Ipv4Addr, sync::Arc};

use chrono::Utc;
use eyre::Context;

use crate::utils::os_version::get_distro;

use super::*;

/// Troubleshoot an SSH server connection
#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct SshTroubleshooter {
    /// The host to connect to and attempt signing in
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    host: Ipv4Addr,

    /// The port of the SSH server
    #[arg(long, short, default_value_t = 22)]
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
}

impl Default for SshTroubleshooter {
    fn default() -> Self {
        SshTroubleshooter {
            host: Ipv4Addr::from(0x7F_00_00_01),
            port: 22,
            user: "root".to_string(),
            password: CheckValue::stdin(),
            local: false,
            external: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl Troubleshooter for SshTroubleshooter {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        let distro = get_distro().context("could not load distribution for ssh check")?;

        Ok(vec![
            filter_check(
                systemd_service_check(if distro.is_deb_based() { "ssh" } else { "sshd" }),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            filter_check(
                openrc_service_check("sshd"),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            binary_ports_check(
                ["sshd"],
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            tcp_connect_check(self.host, self.port),
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"openssh".to_vec(),
                self.host.is_loopback() || self.local,
            ),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
            pam_check(
                Some("sshd"),
                &self.user,
                self.password.clone(),
                self.host.is_loopback() || self.local,
            ),
            passive_tcpdump_check(
                self.port,
                self.external,
                !self.host.is_loopback() && !self.local,
                get_system_logs,
            ),
        ])
    }
}

#[cfg(not(target_os = "linux"))]
impl Troubleshooter for SshTroubleshooter {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![
            tcp_connect_check(self.host, self.port),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
        ])
    }
}

impl SshTroubleshooter {
    fn try_remote_login(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let host = self.host;
        let port = self.port;
        let user = self.user.clone();
        let pass = self
            .password
            .clone()
            .resolve_prompt(tr, "Enter a password to sign into the SSH server with: ")?;

        // Wait one second so that logs generated from here on out are more
        // likely to be related to logging in. Otherwise, the program goes too
        // fast and will catch logs from previous checks; in particular,
        // kex_exchange_identification errors from connecting directly and logs
        // about the download shell being created
        std::thread::sleep(std::time::Duration::from_secs(1));

        let start = Utc::now();

        let check_result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.try_connection(host, port, &user, &pass))
            .into_check_result("Could not attempt the connection to the server");

        let end = Utc::now();

        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        Ok(check_result.merge_overwrite_details(serde_json::json!({
            "system_logs": logs,
        })))
    }

    async fn try_connection(
        &self,
        host: Ipv4Addr,
        port: u16,
        user: &str,
        password: &str,
    ) -> eyre::Result<CheckResult> {
        use russh::client::AuthResult as AR;
        use tokio::time;

        struct Client;

        impl russh::client::Handler for Client {
            type Error = russh::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &russh::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let client_config = russh::client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        };
        let client_config = Arc::new(client_config);
        let mut session = match time::timeout(
            time::Duration::from_secs(5),
            russh::client::connect(client_config, (host, port), Client),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return Ok(CheckResult::fail(
                    "Connection failure when connecting to server",
                    serde_json::json!({
                        "connection_error": format!("{e:?}")
                    }),
                ));
            }
            Err(_) => {
                return Ok(CheckResult::fail(
                    "Timeout when connecting to SSH server",
                    serde_json::json!({}),
                ));
            }
        };

        Ok(
            match time::timeout(
                time::Duration::from_secs(5),
                session.authenticate_password(user, password),
            )
            .await
            {
                Ok(Ok(AR::Success)) => CheckResult::succeed(
                    "Authentication to remote server succeeded",
                    serde_json::json!({}),
                ),
                Ok(Ok(AR::Failure { .. })) => CheckResult::fail(
                    "Authentication attempt failed; auth failure",
                    serde_json::json!({}),
                ),
                Ok(Err(e)) => CheckResult::fail(
                    "Authentication attempt failed; network failure",
                    serde_json::json!({ "connection_error": format!("{e:?}") }),
                ),
                Err(_) => CheckResult::fail(
                    "Authentication attempt failed; timeout",
                    serde_json::json!({}),
                ),
            },
        )
    }
}
