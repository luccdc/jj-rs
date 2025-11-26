//! Provides a handle for a bundled copy of nft, allowing jj to manipulate firewall rules
//! regardless of the host firewall utility in use
//!
//! ```no_run
//! # // don't run the unit test to delete the firewall...
//! # use jj_rs::utils::nft::Nft;
//! # fn test_nft() -> eyre::Result<()> {
//! let nft = Nft::new()?;
//!
//! nft.exec("flush ruleset", None)?;
//! # Ok(())
//! # }
//! # test_nft().expect("could not run nft test");
//! ```
use std::{
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    process::{Command, ExitStatus, Stdio},
};

use eyre::Context;
use flate2::write::GzDecoder;
use nix::sys::memfd::{MFdFlags, memfd_create};

const NFT_BYTES: &[u8] = include_bytes!(std::env!("NFT_GZIPPED"));

/// Handle around the `nft` binary
pub struct Nft {
    nft_file: File,
}

impl Nft {
    /// Create a new nft handle that can be used later to manipulate firewall rules
    pub fn new() -> eyre::Result<Self> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(NFT_BYTES)
            .context("Could not write all nft bytes")?;

        let nft_file = decoder
            .finish()
            .context("Could not finish writing decompressing nft")?;

        Ok(Self { nft_file })
    }

    /// Actually execute an NFT command
    ///
    /// ```no_run
    /// # // don't run the unit test to add a chain called "sneaky_ip"...
    /// # use jj_rs::utils::nft::Nft;
    /// # fn test_nft() -> eyre::Result<()> {
    /// let nft = Nft::new()?;
    ///
    /// nft.exec("add table inet sneaky_shell", None)?;
    /// # Ok(())
    /// # }
    /// # test_nft().expect("could not run nft test");
    /// ```
    pub fn exec<R: AsRef<str>, S: Into<Option<Stdio>>>(
        &self,
        command: R,
        stderr: S,
    ) -> eyre::Result<ExitStatus> {
        Command::new(format!("/proc/self/fd/{}", self.nft_file.as_raw_fd()))
            .arg(command.as_ref())
            .stderr(stderr.into().unwrap_or_else(Stdio::inherit))
            .stdout(Stdio::inherit())
            .spawn()
            .context("Could not spawn nft")?
            .wait()
            .context("Could not wait for NFT to finish execution")
    }

    /// Create a new [`std::process::Command`] object to perform further
    /// customization around later
    pub fn command(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.nft_file.as_raw_fd()))
    }
}
