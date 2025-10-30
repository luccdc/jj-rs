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
    sys::memfd::{memfd_create, MFdFlags},
    unistd::execv,
};

use crate::utils::busybox::str_to_cstr;

/// Runs an embedded copy of jq
///
/// Use it by specifying -- and then arguments to pass to nft, e.g.:
///
/// ```sh
/// jj-rs nft -- add table inet core
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Jq {
    /// Arguments to pass to the nft binary
    args: Vec<String>,
}

const JQ_BYTES: &'static [u8] = include_bytes!(std::env!("JQ_GZIPPED"));

impl super::Command for Jq {
    fn execute(self) -> anyhow::Result<()> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(JQ_BYTES)
            .context("Could not write all jq bytes")?;

        let jq_file = decoder
            .finish()
            .context("Could not finish writing decompressing jq")?;

        let args = str_to_cstr(&self.args)?;

        execv(
            &CString::from_str(&format!("/proc/self/fd/{}", jq_file.as_raw_fd()))
                .context("Could not find file path to load busybox")?,
            &args,
        )
        .context("Failed to perform execv")?;

        unreachable!()
    }
}
