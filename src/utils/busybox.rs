//! This module is intended for use when shell utilities are desired, but strict
//! portability is also required. It allows loading a copy of busybox coreutils
//! into memory and then executing them fully as shell commands
//!
//! ```
//! # use jj_rs::utils::busybox::Busybox;
//! # fn test_busybox() -> anyhow::Result<()> {
//! let busybox = Busybox::new()?;
//!
//! assert_eq!(busybox.execute(&["uname"])?, "Linux\n");
//!
//! // Acquire a regular standard library Command object to use features
//! // such as output management, exit code use, argument management, and
//! // environment management
//! let mut cmd: std::process::Command = busybox.command("uname");
//! let output = cmd.spawn()?.wait()?;
//! # Ok(())
//! # }
//! # test_busybox().expect("could not run busybox test");
//! ```
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

use anyhow::{Context, bail};
use flate2::write::GzDecoder;
use nix::{
    sys::memfd::{MFdFlags, memfd_create},
    unistd::execv,
};

const BUSYBOX_BYTES: &'static [u8] = include_bytes!(std::env!("BUSYBOX_GZIPPED"));

/// Utility function for converting a list of Strings or strs to a list CStrings
pub fn str_to_cstr<R: AsRef<str>>(args: &[R]) -> anyhow::Result<Vec<CString>> {
    args.iter()
        .map(|arg| CString::from_str(&arg.as_ref()))
        .collect::<Result<Vec<CString>, _>>()
        .context("Could not convert list of strings to list of cstrings")
}

/// A handle for an instance of Busybox
///
/// ```
/// # use jj_rs::utils::busybox::Busybox;
/// # fn test_busybox() -> anyhow::Result<()> {
/// let busybox = Busybox::new()?;
///
/// assert_eq!(busybox.execute(&["uname"])?, "Linux\n");
///
/// // Acquire a regular standard library Command object to use features
/// // such as output management, exit code use, argument management, and
/// // environment management
/// let mut cmd: std::process::Command = busybox.command("uname");
/// let output = cmd.spawn()?.wait()?;
/// # Ok(())
/// # }
/// # test_busybox().expect("could not run busybox test");
/// ```
pub struct Busybox {
    busybox_file: File,
}

impl Busybox {
    /// Creates a new Busybox container, loading Busybox into memory and preparing to
    /// execute commands
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
    pub fn execv<R: AsRef<str>>(&self, args: &[R]) -> anyhow::Result<()> {
        let args = str_to_cstr(args)?;

        execv(
            &CString::from_str(&format!("/proc/self/fd/{}", self.busybox_file.as_raw_fd()))
                .context("Could not find file path to load busybox")?,
            &args,
        )
        .context("Failed to perform execv")?;

        Ok(())
    }

    /// Executes a command and returns the result as a string.
    ///
    /// ```
    /// # use jj_rs::utils::busybox::Busybox;
    /// # fn test_busybox() -> anyhow::Result<()> {
    /// let busybox = Busybox::new()?;
    ///
    /// assert_eq!(busybox.execute(&["uname"])?, "Linux\n");
    ///
    /// // Acquire a regular standard library Command object to use features
    /// // such as output management, exit code use, argument management, and
    /// // environment management
    /// let mut cmd: std::process::Command = busybox.command("uname");
    /// let output = cmd.spawn()?.wait()?;
    /// # Ok(())
    /// # }
    /// # test_busybox().expect("could not run busybox test");
    /// ```
    pub fn execute<R: AsRef<OsStr>>(&self, command: &[R]) -> anyhow::Result<String> {
        let Some(cmd) = command.get(0) else {
            bail!("Command not fully specified; empty list provided to Busybox::execute");
        };

        let output = self
            .command(cmd)
            .args(&command[1..])
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

/// Utility function for easily running a single busybox command
///
/// ```
/// # use jj_rs::utils::busybox::execute;
/// # fn test_busybox() -> anyhow::Result<()> {
/// assert_eq!(execute(&["uname"])?, "Linux\n");
/// # Ok(())
/// # }
/// # assert!(test_busybox().is_ok());
/// ```
#[allow(dead_code)]
pub fn execute<R: AsRef<OsStr>>(args: &[R]) -> anyhow::Result<String> {
    let busybox = Busybox::new()?;
    busybox.execute(args)
}
