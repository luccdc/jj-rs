use std::{
    ffi::OsStr,
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    process::{Command, ExitStatus, Stdio},
};

use anyhow::Context;
use flate2::write::GzDecoder;
use nix::sys::memfd::{MFdFlags, memfd_create};

const TCPDUMP_BYTES: &'static [u8] = include_bytes!(std::env!("TCPDUMP_GZIPPED"));

pub struct Tcpdump {
    tcpdump_file: File,
}

impl Tcpdump {
    pub fn new() -> anyhow::Result<Self> {
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

    #[allow(dead_code)]
    pub fn command_inst(&self) -> Command {
        Command::new(&format!("/proc/self/fd/{}", self.tcpdump_file.as_raw_fd()))
    }

    pub fn command<R: AsRef<OsStr>, S: Into<Option<Stdio>>>(
        &self,
        args: &[R],
        stderr: S,
    ) -> anyhow::Result<ExitStatus> {
        Command::new(&format!("/proc/self/fd/{}", self.tcpdump_file.as_raw_fd()))
            .args(args)
            .stderr(stderr.into().unwrap_or_else(Stdio::inherit))
            .stdout(Stdio::inherit())
            .spawn()
            .context("Could not spawn tcpdump")?
            .wait()
            .context("Could not wait for tcpdump to finish execution")
    }
}
