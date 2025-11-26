use std::{
    ffi::CString,
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    str::FromStr,
};

use clap::Parser;
use eyre::Context;
use flate2::write::GzDecoder;
use nix::{
    sys::memfd::{MFdFlags, memfd_create},
    unistd::execv,
};

use crate::utils::busybox::str_to_cstr;

/// Runs an embedded copy of tmux
///
/// ```sh
/// jj-rs tmux
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Tmux {
    /// Arguments to pass to the nft binary
    args: Vec<String>,
}

const TMUX_BYTES: &[u8] = include_bytes!(std::env!("TMUX_GZIPPED"));

impl super::Command for Tmux {
    fn execute(self) -> eyre::Result<()> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(TMUX_BYTES)
            .context("Could not write all tmux bytes")?;

        let tmux_file = decoder
            .finish()
            .context("Could not finish writing decompressing tmux")?;

        let args = str_to_cstr(&self.args)?;

        execv(
            &CString::from_str(&format!("/proc/self/fd/{}", tmux_file.as_raw_fd()))
                .context("Could not find file path to load busybox")?,
            &args,
        )
        .context("Failed to perform execv")?;

        unreachable!()
    }
}
