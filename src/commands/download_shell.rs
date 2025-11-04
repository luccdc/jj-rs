use std::{
    fs::File,
    io::prelude::*,
    net::Ipv4Addr,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    process::{Command, exit},
};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use flate2::write::GzDecoder;
use nix::{
    sys::{
        memfd::{MFdFlags, memfd_create},
        wait::waitpid,
    },
    unistd::{ForkResult, fork},
};

use crate::utils::{busybox::Busybox, download_container::DownloadContainer, passwd::load_users};

use super::zsh::ZSH_BYTES;

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShellType {
    Zsh,
    Sh,
    Bash,
}

/// Spawns a download shell to circumvent the local outbound firewall
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct DownloadShell {
    /// The sneaky IP address to use for outbound traffic
    #[arg(long, short)]
    sneaky_ip: Option<Ipv4Addr>,

    /// Specify a name for the container, compared to auto generated names
    #[arg(long, short)]
    name: Option<String>,

    /// Specify which shell to use for the download shell. Bash depends on the system, sh uses busybox, and zsh is embedded
    #[arg(value_enum, long, short = 'S', default_value_t = ShellType::Zsh)]
    shell: ShellType,

    /// A command to run in the container instead of providing a shell
    command: Vec<String>,
}

fn zsh_command() -> anyhow::Result<(OwnedFd, Command)> {
    let temp_fd = memfd_create("", MFdFlags::empty())?;
    let raw_fd = temp_fd.into_raw_fd();

    let temp_file = unsafe { File::from_raw_fd(raw_fd) };
    let mut decoder = GzDecoder::new(temp_file);

    decoder.write_all(ZSH_BYTES)?;

    let zsh_file = decoder.finish()?;
    let raw_fd = zsh_file.into_raw_fd();

    Ok((
        unsafe { OwnedFd::from_raw_fd(raw_fd) },
        Command::new(&format!("/proc/self/fd/{raw_fd}")),
    ))
}

impl super::Command for DownloadShell {
    fn execute(mut self) -> anyhow::Result<()> {
        let container = DownloadContainer::new(self.name.take(), self.sneaky_ip.clone())?;

        let bash_cmd = format!(
            r#"exec bash --rcfile <(cat ~/.bashrc 2>/dev/null || cat /etc/bashrc 2>/dev/null || echo 'export PS1="\u@\h:\w\$ "'; echo 'PS1="\033[0;32m({})\033[0m $PS1"')"#,
            container.name()
        );

        let zsh_ps1 = format!("%F{{green}}({})%f %n@%m %~%# ", container.name());

        let sh_ps1 = format!(r"\033[0;32m({})\033[0m \u@\h:\w\$ ", container.name());

        container.run(|| -> anyhow::Result<()> {
            match (
                std::env::var("SUDO_UID")
                    .ok()
                    .and_then(|uid| uid.parse::<u32>().ok()),
                self.shell,
                self.command.is_empty(),
            ) {
                (Some(uid), ShellType::Zsh, true) => match unsafe { fork()? } {
                    ForkResult::Child => {
                        let _ = nix::unistd::setuid(uid.into());

                        let (fd, mut cmd) = zsh_command()?;

                        let users = load_users(&format!("{uid}"))?;
                        if let Some(user) = users.get(0) {
                            cmd.env("HOME", user.home.clone());
                        }
                        if let Ok(user) = std::env::var("SUDO_USER") {
                            cmd.env("USER", user);
                        }

                        cmd.env("PS1", zsh_ps1);

                        let mut child = match cmd.spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = child.wait() {
                            eprintln!("Could not wait for command to finish! {e}");
                            exit(127);
                        };
                        drop(fd);
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        waitpid(child, None).context("Could not wait for child to die")?;
                    }
                },
                (Some(uid), ShellType::Sh, true) => match unsafe { fork()? } {
                    ForkResult::Child => {
                        let _ = nix::unistd::setuid(uid.into());

                        let bb = Busybox::new()?;
                        let mut cmd = bb.command("sh");

                        let users = load_users(&format!("{uid}"))?;
                        if let Some(user) = users.get(0) {
                            cmd.env("HOME", user.home.clone());
                        }
                        if let Ok(user) = std::env::var("SUDO_USER") {
                            cmd.env("USER", user);
                        }

                        cmd.env("PS1", sh_ps1);

                        let mut child = match cmd.spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = child.wait() {
                            eprintln!("Could not wait for command to finish! {e}");
                            exit(127);
                        };
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        waitpid(child, None).context("Could not wait for child to die")?;
                    }
                },
                (Some(uid), ShellType::Bash, true) => match unsafe { fork()? } {
                    ForkResult::Child => {
                        let _ = nix::unistd::setuid(uid.into());

                        let mut cmd = Command::new("bash");
                        cmd.args(&["-c", &bash_cmd]);

                        let users = load_users(&format!("{uid}"))?;
                        if let Some(user) = users.get(0) {
                            cmd.env("HOME", user.home.clone());
                        }
                        if let Ok(user) = std::env::var("SUDO_USER") {
                            cmd.env("USER", user);
                        }

                        let mut child = match cmd.spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = child.wait() {
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

                        let mut cmd = Command::new(&self.command[0]);
                        cmd.args(&self.command[1..]);

                        let users = load_users(&format!("{uid}"))?;
                        if let Some(user) = users.get(0) {
                            cmd.env("HOME", user.home.clone());
                        }
                        if let Ok(user) = std::env::var("SUDO_USER") {
                            cmd.env("USER", user);
                        }

                        let mut child = match cmd.spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Could not spawn command! {e}");
                                exit(127);
                            }
                        };
                        if let Err(e) = child.wait() {
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
                (_, ShellType::Sh, _) => {
                    let bb = Busybox::new()?;

                    bb.command("sh").env("PS1", sh_ps1).spawn()?.wait()?;
                }
                (_, ShellType::Bash, _) => {
                    Command::new("bash")
                        .args(&["-c", &bash_cmd])
                        .spawn()?
                        .wait()?;
                }
                (_, ShellType::Zsh, _) => {
                    let (fd, mut cmd) = zsh_command()?;
                    cmd.env("PS1", zsh_ps1).spawn()?.wait()?;
                    drop(fd);
                }
            }

            Ok(())
        })??;

        Ok(())
    }
}
