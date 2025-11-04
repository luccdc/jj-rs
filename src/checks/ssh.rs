use std::net::Ipv4Addr;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use serde_json::{json, value::Value};

use crate::utils::{
    distro::get_distro,
    qx,
    systemd::{get_service_info, is_service_active},
};

use super::{CheckResult, CheckValue, Troubleshooter, TroubleshooterRunner, check_fn};

#[derive(Parser, Deserialize, Debug)]
pub struct SshTroubleshooter {
    #[arg(long, short = 'H')]
    host: Option<Ipv4Addr>,
    #[arg(long, short)]
    port: Option<u16>,
    #[arg(long, short)]
    user: Option<String>,
    #[arg(long, short = 'P')]
    password: Option<CheckValue>,
}

impl SshTroubleshooter {
    fn check_systemd_running(&self) -> anyhow::Result<CheckResult> {
        if self.host.is_some() {
            return Ok(CheckResult::not_run(
                "Cannot check systemd service on remote host".to_string(),
                Value::Null,
            ));
        }

        if qx("which systemctl 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`systemctl` not found on host".to_string(),
                Value::Null,
            ));
        }

        let service_name = match get_distro().context("could not load distribution for check")? {
            Some(d) if d.is_deb_based() => "ssh",
            _ => "sshd",
        };

        let service_info = get_service_info(service_name)?;

        if is_service_active(&service_info) {
            Ok(CheckResult::succeed(
                "systemd service is active".to_string(),
                json!({
                   "main_pid": service_info.get("MainPID"),
                   "running_since": service_info.get("ExecMainStartTimestamp")
                }),
            ))
        } else {
            Ok(CheckResult::fail(
                "systemd service is not active".to_string(),
                json!({
                   "stopped_since": service_info.get("InactiveEnterTimestamp")
                }),
            ))
        }
    }

    fn try_remote_login(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let _host = self.host.unwrap_or(Ipv4Addr::from_octets([127, 0, 0, 1]));
        let _port = self.port.unwrap_or(22);
        let _user = self.user.clone().unwrap_or("root".to_string());
        let _pass = self
            .password
            .clone()
            .unwrap_or(CheckValue::Stdin)
            .resolve_prompt(
                tr,
                "Enter a password to sign into the SSH server with: ".to_string(),
            )?;

        Ok(CheckResult::not_run(
            "not implemented".to_string(),
            Value::Null,
        ))
    }
}

impl Troubleshooter for SshTroubleshooter {
    fn checks<'a>(&'a self) -> Vec<Box<dyn super::CheckStep<'a> + 'a>> {
        vec![
            check_fn("Check systemd service", |_| self.check_systemd_running()),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
        ]
    }
}
