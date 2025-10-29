use std::{
    ffi::CString,
    fs::File,
    io::prelude::*,
    os::fd::{FromRawFd, IntoRawFd},
    str::FromStr,
};

use anyhow::Context;
use clap::Parser;
use flate2::write::GzDecoder;
use nix::sys::memfd::{memfd_create, MFdFlags};

/// Runs an embedded copy of busybox
///
/// Use it by specifying -- and then arguments to pass to busybox, e.g.:
///
/// ```sh
/// jj-rs busybox -- ls -al
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Busybox {
    /// Arguments to pass to the busybox binary
    args: Vec<String>,
}

impl super::Command for Busybox {
    fn execute(self) -> anyhow::Result<()> {
        let temp_fd =
            memfd_create("", MFdFlags::MFD_CLOEXEC).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(include_bytes!(std::env!("BUSYBOX_GZIPPED")))
            .context("Could not write all busybox bytes")?;

        let finished_file = decoder.finish();

        let args = if self.args.is_empty() {
            &["busybox".to_string()][..]
        } else {
            &self.args
        };

        let args = args
            .iter()
            .map(|arg| CString::from_str(&arg))
            .collect::<Result<Vec<_>, _>>()
            .context("Encountered a non-ASCII character as an argument to busybox")?;

        nix::unistd::execv(
            &CString::from_str(&format!("/proc/self/fd/{fd}"))
                .context("Could not format file path to load busybox")?,
            &args,
        )
        .context("Failed to execv")?;

        // Hold on to fnished_file until after execve; it can't
        // drop before then
        drop(finished_file);

        Ok(())
    }
}
