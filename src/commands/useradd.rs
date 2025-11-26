use eyre::bail;
use nix::unistd::geteuid;

use crate::{
    strvec,
    utils::{busybox::Busybox, distro::get_distro},
};

/// Add backup users to the system
#[derive(clap::Parser, Debug)]
#[command(version, about)]
pub struct Useradd {
    /// Backup users to add
    #[arg(
        short, long,
        default_values_t = strvec!["redboi", "blueguy"]
    )]
    users: Vec<String>,
}

impl super::Command for Useradd {
    fn execute(self) -> eyre::Result<()> {
        if !geteuid().is_root() {
            bail!("You must be root to add backup users");
        }

        let bb = Busybox::new()?;

        let sudo_group = match get_distro()? {
            Some(d) if d.is_deb_based() => "sudo",
            _ => "wheel",
        };

        for user in self.users {
            println!("Adding user {user}");
            bb.command("adduser")
                .args(["-S", "-s", "/bin/sh", "-G", sudo_group, &user])
                .spawn()?
                .wait()?;
            bb.command("passwd").arg(user).spawn()?.wait()?;
        }

        Ok(())
    }
}
