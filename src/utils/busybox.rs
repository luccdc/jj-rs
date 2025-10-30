use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::prelude::*,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
    str::FromStr,
};

use anyhow::Context;
use flate2::write::GzDecoder;
use nix::{
    sys::memfd::{memfd_create, MFdFlags},
    unistd::execv,
};

const BUSYBOX_BYTES: &'static [u8] = include_bytes!(std::env!("BUSYBOX_GZIPPED"));

fn str_to_cstr<R: AsRef<str>>(args: &[R]) -> anyhow::Result<Vec<CString>> {
    args.iter()
        .map(|arg| CString::from_str(&arg.as_ref()))
        .collect::<Result<Vec<CString>, _>>()
        .context("Could not convert arguments for busybox")
}

pub struct Busybox {
    busybox_file: File,
}

impl Busybox {
    pub fn new() -> anyhow::Result<Self> {
        let temp_fd =
            memfd_create("", MFdFlags::empty()).context("Could not create memory file")?;

        let fd = temp_fd.into_raw_fd();

        let temp_file = unsafe { File::from_raw_fd(fd) };
        let mut decoder = GzDecoder::new(temp_file);

        decoder
            .write_all(BUSYBOX_BYTES)
            .context("Could not write all busybox bytes")?;

        let busybox_file = decoder
            .finish()
            .context("Could not finish writing decompressing busybox")?;

        Ok(Self { busybox_file })
    }

    /// Replaces the current process with busybox
    ///
    /// In the happy path, good case, this function will fail to return
    pub fn execv<R: AsRef<str>>(self, args: &[R]) -> anyhow::Result<()> {
        let args = str_to_cstr(args)?;

        execv(
            &CString::from_str(&format!("/proc/self/fd/{}", self.busybox_file.as_raw_fd()))
                .context("Could not find file path to load busybox")?,
            &args,
        )
        .context("Failed to perform execv")?;

        Ok(())
    }

    /// Executes a command and returns the result as a string. Shorthand for
    /// `system`
    ///
    /// Alias of Perl's qx
    ///
    /// Not as safe as using execute, since this will shell out and
    /// use system level utilities in $PATH instead of the embedded busybox
    /// utilities. Useful if doing things with systemd or curl, stuff
    /// not supported by busybox, but for portability prefer to use
    /// execute instead
    pub fn qx(&self, command: &str) -> anyhow::Result<String> {
        let output = self
            .command("sh")
            .args(&["-c", command])
            .stderr(Stdio::piped())
            .output()?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Constructs a std::process::Command object that makes use of the
    /// internal Busybox implementation
    pub fn command<R: AsRef<OsStr>>(&self, cmd: R) -> Command {
        let mut cmd_obj = Command::new(&format!("/proc/self/fd/{}", self.busybox_file.as_raw_fd()));
        cmd_obj.arg0(cmd);
        cmd_obj
    }
}
