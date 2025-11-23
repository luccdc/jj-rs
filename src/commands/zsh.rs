use std::{
    ffi::CString,
    fs::File,
    io::prelude::*,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::PermissionsExt,
    },
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context;
use clap::Parser;
use flate2::write::GzDecoder;
use nix::{
    sys::memfd::{MFdFlags, memfd_create},
    unistd::execv,
};

use crate::utils::busybox::str_to_cstr;

/// Runs an embedded copy of zsh
///
/// MWCCDC often provides copies of bash that are modified to load `PROMPT_COMMAND`
/// from somewhere that deletes all firewall rules...
///
/// Use it by specifying -- and then arguments to pass to zsh, e.g.:
///
/// ```sh
/// exec jj-rs zsh
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Zsh {
    /// Install as a valid shell
    #[arg(short, long)]
    install: bool,

    /// Where to install the shell
    #[arg(short = 'p', long, default_value = "/usr/local/bin/jj-zsh")]
    install_path: PathBuf,

    /// Change the shell for the specified user to the installed version of zsh
    #[arg(short, long)]
    chsh: Option<String>,

    /// Arguments to pass to the zsh binary
    args: Vec<String>,
}

pub const ZSH_BYTES: &[u8] = include_bytes!(std::env!("ZSH_GZIPPED"));

impl super::Command for Zsh {
    fn execute(self) -> anyhow::Result<()> {
        if self.install {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&self.install_path)?;
            file.set_permissions(PermissionsExt::from_mode(0o755))?;

            let current_file = std::env::args()
                .next()
                .ok_or(anyhow::anyhow!("Could not get current binary"))?;

            writeln!(file, "#!{} zsh", &current_file)?;
            writeln!(file, "exec {} zsh $@", &current_file)?;

            println!("Successfully installed!");
        }

        if let Some(user) = self.chsh.as_ref() {
            let passwd = &std::fs::read("/etc/passwd")?;
            let passwd = String::from_utf8_lossy(passwd);
            let passwd = passwd
                .split('\n')
                .map(|line| {
                    if line.starts_with(user) {
                        let mut parts = line.split(':').map(str::to_string).collect::<Vec<_>>();
                        if !parts.is_empty() {
                            let len = parts.len();
                            parts[len - 1] = self.install_path.display().to_string();
                        }
                        parts.join(":")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write("/etc/passwd", passwd)?;

            println!("Successfully changed shell for user!");
        }

        if self.install || self.chsh.is_some() {
            return Ok(());
        }

        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(ZSH_BYTES)
            .context("Could not write all zsh bytes")?;

        let zsh_file = decoder
            .finish()
            .context("Could not finish writing decompressing zsh")?;

        let args = str_to_cstr(&self.args)?;

        execv(
            &CString::from_str(&format!("/proc/self/fd/{}", zsh_file.as_raw_fd()))
                .context("Could not find file path to load busybox")?,
            &args,
        )
        .context("Failed to perform execv")?;

        unreachable!()
    }
}
