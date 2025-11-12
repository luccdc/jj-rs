use std::net::Ipv4Addr;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use serde_json::value::Value;

use crate::utils::distro::get_distro;

use super::{
    CheckResult, CheckValue, TcpdumpProtocol, Troubleshooter, TroubleshooterRunner, check_fn,
    filter_check, openrc_service_check, systemd_service_check, tcp_connect_check, tcpdump_check,
};

#[derive(Parser, Deserialize, Debug)]
pub struct SshTroubleshooter {
    #[arg(long, short = 'H')]
    host: Option<Ipv4Addr>,

    #[arg(long, short, default_value_t = 22)]
    port: u16,

    #[arg(long, short)]
    user: Option<String>,

    #[arg(long, short = 'P', default_value_t = Default::default())]
    password: CheckValue,

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
                self.host.is_none() || self.local,
                "Cannot check systemd service on remote host",
            ),
            filter_check(
                openrc_service_check("sshd"),
                self.host.is_none() || self.local,
                "Cannot check openrc service on remote host",
            ),
            tcp_connect_check(self.get_host(), self.port),
            tcpdump_check(
                self.get_host(),
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
    fn get_host(&self) -> Ipv4Addr {
        self.host.unwrap_or(Ipv4Addr::from_octets([127, 0, 0, 1]))
    }

    fn try_remote_login(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let _host = self.get_host();
        let _port = self.port;
        let _user = self.user.clone().unwrap_or("root".to_string());
        let _pass = self
            .password
            .clone()
            .resolve_prompt(tr, "Enter a password to sign into the SSH server with: ")?;

        Ok(CheckResult::not_run(
            "not implemented".to_string(),
            Value::Null,
        ))
    }
}
