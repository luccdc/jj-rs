use std::{
    ffi::CString,
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
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

/// Represents a copy of busybox loaded and ready to execute shell commands
pub struct Busybox {
    busybox_file: File,
}

impl Busybox {
    pub fn new() -> anyhow::Result<Self> {
        let temp_fd =
            memfd_create("", MFdFlags::MFD_CLOEXEC).context("Could not create memory file")?;

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
}
