use std::{
    net::Ipv4Addr,
    process::{exit, Command},
};

use anyhow::Context;
use clap::Parser;
use nix::{
    sys::wait::waitpid,
    unistd::{fork, ForkResult},
};

use crate::utils::{busybox::Busybox, download_container::DownloadContainer};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct DownloadShell {
    #[arg(long, short)]
    sneaky_ip: Option<Ipv4Addr>,

    #[arg(long, short)]
    name: Option<String>,

    /// Uses sh instead of bash for the interactive login. Should only be used in situations such as
    /// running on Alpine
    #[arg(long, short)]
    use_sh: bool,

    command: Vec<String>,
}

impl super::Command for DownloadShell {
    fn execute(mut self) -> anyhow::Result<()> {
        let container = DownloadContainer::new(self.name.take(), self.sneaky_ip.clone())?;

        let bash_cmd = format!(
            r#"exec bash --login -i -c 'export PS1="\033[0;32m({})\033[0m $PS1"; exec bash --login -i'"#,
            container.name()
        );

        container.run(|| -> anyhow::Result<()> {
            match (
                std::env::var("SUDO_UID")
                    .ok()
                    .and_then(|uid| uid.parse::<u32>().ok()),
                self.use_sh,
                self.command.is_empty(),
            ) {
                (Some(uid), _, true) => match unsafe { fork()? } {
                    ForkResult::Child => {
                        let _ = nix::unistd::setuid(uid.into());

                        let mut cmd = match Command::new("sh").args(&["-c", &bash_cmd]).spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = cmd.wait() {
                            eprintln!("Could not wait for command to finish! {e}");
                            exit(127);
                        };
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        waitpid(child, None).context("Could not wait for child to die")?;
                    }
                },
                (Some(uid), _, false) => match unsafe { fork()? } {
                    ForkResult::Child => {
                        let _ = nix::unistd::setuid(uid.into());

                        let mut cmd = match Command::new(&self.command[0])
                            .args(&self.command[1..])
                            .spawn()
                        {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = cmd.wait() {
                            eprintln!("Could not wait for command to finish! {e}");
                            exit(127);
                        };
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        waitpid(child, None)?;
                    }
                },
                (_, _, false) => {
                    Command::new(&self.command[0])
                        .args(&self.command[1..])
                        .spawn()?
                        .wait()?;
                }
                (_, true, _) => {
                    let bb = Busybox::new()?;

                    bb.command("sh").spawn()?.wait()?;
                }
                (_, false, _) => {
                    Command::new("sh")
                        .args(&["-c", &bash_cmd])
                        .spawn()?
                        .wait()?;
                }
            }

            Ok(())
        })??;

        Ok(())
    }
}
