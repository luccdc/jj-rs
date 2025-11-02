use std::{
    ffi::CString,
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
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
/// MWCCDC often provides copies of bash that are modified to load PROMPT_COMMAND
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
    /// Arguments to pass to the zsh binary
    args: Vec<String>,
}

const ZSH_BYTES: &'static [u8] = include_bytes!(std::env!("ZSH_GZIPPED"));

impl super::Command for Zsh {
    fn execute(self) -> anyhow::Result<()> {
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
