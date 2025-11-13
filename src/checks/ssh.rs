use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context;
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use jj_rs::utils::qx;
use serde::Deserialize;

use crate::{checks::IntoCheckResult, utils::distro::get_distro};

use super::{
    CheckResult, CheckValue, TcpdumpProtocol, Troubleshooter, TroubleshooterRunner, check_fn,
    filter_check, openrc_service_check, systemd_service_check, tcp_connect_check, tcpdump_check,
};

/// Troubleshoot an SSH server connection
#[derive(Parser, Deserialize, Debug)]
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

    /// [CheckValue] The password to authenticate with
    #[arg(long, short = 'P', default_value_t = Default::default())]
    password: CheckValue,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    local: bool,
}

impl Troubleshooter for SshTroubleshooter {
    fn checks<'a>(&'a self) -> anyhow::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        let distro = get_distro().context("could not load distribution for ssh check")?;

        Ok(vec![
            filter_check(
                systemd_service_check(match &distro {
                    Some(d) if d.is_deb_based() => "ssh",
                    _ => "sshd",
                }),
                self.host.is_loopback(),
                "Cannot check systemd service on remote host",
            ),
            filter_check(
                openrc_service_check("sshd"),
                self.host.is_loopback(),
                "Cannot check openrc service on remote host",
            ),
            tcp_connect_check(self.host, self.port),
            tcpdump_check(
                self.host,
                self.port,
                TcpdumpProtocol::Tcp,
                b"openssh".to_vec(),
                self.local,
            ),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
        ])
    }
}

impl SshTroubleshooter {
    fn try_remote_login(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let host = self.host;
        let port = self.port;
        let user = self.user.clone();
        let pass = self
            .password
            .clone()
            .resolve_prompt(tr, "Enter a password to sign into the SSH server with: ")?;

        let start = Utc::now();

        let check_result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.try_connection(host, port, &user, &pass))
            .into_check_result("Could not ");

        let end = Utc::now();

        use serde_json::value::Value;
        let logs = if self.local || host.is_loopback() {
            match self.get_logs(start, end) {
                Ok(v) => v.map(|v2| v2.into_iter().map(Value::String).collect::<Value>()),
                Err(e) => Some(Value::String(format!("Could not pull system logs: {e:?}"))),
            }
        } else {
            None
        };

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
    ) -> anyhow::Result<CheckResult> {
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

        use tokio::time;
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

        use russh::client::AuthResult as AR;

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

    fn get_logs(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<Option<Vec<String>>> {
        if !qx("which journalctl 2>/dev/null")?.1.is_empty() {
            return Ok(Some(self.get_logs_systemd(start, end)?));
        }

        Ok(None)
    }

    fn get_logs_systemd(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<Vec<String>> {
        let start = start.with_timezone(&Local);
        let end = end.with_timezone(&Local);

        let format = "%Y-%m-%d %H:%M:%S";

        qx(&format!(
            "journalctl --no-pager '--since={}' '--until={}' --utc",
            start.format(format),
            end.format(format)
        ))
        .map(|(_, o)| o.trim().split("\n").map(String::from).collect())
    }
}
