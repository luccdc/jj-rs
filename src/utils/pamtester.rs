//! Provides a handle for a bundled copy of pamtester, allowing jj to try and
//! test different PAM services
//!
//! ```no_run
//! # // don't run the unit test to authenticate as root...
//! # use jj_rs::utils::pamtester::Pamtester;
//! # fn test_pamtester() -> anyhow::Result<()> {
//! let pamtester = Pamtester::new()?;
//! pamtester.command().args(["login", "root", "authenticate"]).spawn()?.wait()?;
//! # Ok(())
//! # }
//! # test_pamtester().expect("could not run pamtester test");
//! ```
use std::{
    fs::File,
    io::prelude::*,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
    process::Command,
};

use anyhow::Context;
use flate2::write::GzDecoder;
use nix::sys::memfd::{MFdFlags, memfd_create};

const PAMTESTER_BYTES: &[u8] = include_bytes!(std::env!("PAMTESTER_GZIPPED"));

/// Handle around the `pamtester` binary
pub struct Pamtester {
    pamtester_file: File,
}

impl Pamtester {
    /// Create a new pamtester handle that can be used later to manipulate firewall rules
    pub fn new() -> anyhow::Result<Self> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(PAMTESTER_BYTES)
            .context("Could not write all pamtester bytes")?;

        let pamtester_file = decoder
            .finish()
            .context("Could not finish writing decompressing pamtester")?;

        Ok(Self { pamtester_file })
    }

    /// Create a new [`std::process::Command`] object to perform further
    /// customization around later
    pub fn command(&self) -> Command {
        let mut cmd_obj =
            Command::new(format!("/proc/self/fd/{}", self.pamtester_file.as_raw_fd()));
        cmd_obj.arg0("pamtester");
        cmd_obj
    }
}
