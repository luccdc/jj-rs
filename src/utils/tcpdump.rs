//! Provides a handle for a bundled copy of tcpdump
//!
//! Since this uses the Command module from the standard library,
//! it is possible to prepare to read from standard out to perform
//! some basic analysis of the output. The [BufRead trait](https://doc.rust-lang.org/std/io/trait.BufRead.html) may prove
//! to be particularly helpful
//!
//! ```no_run
//! # use std::{io::{BufReader, prelude::*}, process::Stdio};
//! # use eyre::eyre;
//! # use jj_rs::utils::tcpdump::Tcpdump;
//! # fn test_tcpdump() -> eyre::Result<()> {
//! let tcpdump = Tcpdump::new()?;
//! let mut command: std::process::Command = tcpdump.command_inst();
//!
//! let mut child = command
//!     .stdout(Stdio::inherit())
//!     .spawn()?;
//!
//! let stdout = child.stdout.take().ok_or(eyre!("Could not get stdout"))?;
//! let mut stdout = BufReader::new(stdout);
//!
//! for line in stdout.lines() {
//!     let line = line?;
//!     println!("{line}");
//! }
//! # Ok(())
//! # }
//! # test_tcpdump().expect("could not run tcpdump test");
//! ```
use std::{
    ffi::OsStr,
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    process::{Command, ExitStatus, Stdio},
};

use eyre::Context;
use flate2::write::GzDecoder;
use nix::sys::memfd::{MFdFlags, memfd_create};

const TCPDUMP_BYTES: &[u8] = include_bytes!(std::env!("TCPDUMP_GZIPPED"));

/// Handle around the `tcpdump` binary
pub struct Tcpdump {
    tcpdump_file: File,
}

impl Tcpdump {
    /// Create a new Tcpdump handle to prepare for execution of commands
    pub fn new() -> eyre::Result<Self> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(TCPDUMP_BYTES)
            .context("Could not write all tcpdump bytes")?;

        let tcpdump_file = decoder
            .finish()
            .context("Could not finish writing decompressing tcpdump")?;

        Ok(Self { tcpdump_file })
    }

    /// Return a new Command object to prepare for reading from it later
    #[allow(dead_code)]
    pub fn command_inst(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.tcpdump_file.as_raw_fd()))
    }

    /// Spawn tcpdump with the specified arguments to show results to the operator
    pub fn command<R: AsRef<OsStr>, S: Into<Option<Stdio>>>(
        &self,
        args: &[R],
        stderr: S,
    ) -> eyre::Result<ExitStatus> {
        Command::new(format!("/proc/self/fd/{}", self.tcpdump_file.as_raw_fd()))
            .args(args)
            .stderr(stderr.into().unwrap_or_else(Stdio::inherit))
            .stdout(Stdio::inherit())
            .spawn()
            .context("Could not spawn tcpdump")?
            .wait()
            .context("Could not wait for tcpdump to finish execution")
    }
}
