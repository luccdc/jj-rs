use std::{
    fs::File,
    io::prelude::*,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    process::{Command, Stdio},
};

use anyhow::Context;
use flate2::write::GzDecoder;
use nix::sys::memfd::{MFdFlags, memfd_create};

const NFT_BYTES: &'static [u8] = include_bytes!(std::env!("NFT_GZIPPED"));

pub struct Nft {
    nft_file: File,
}

impl Nft {
    pub fn new() -> anyhow::Result<Self> {
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

    pub fn exec<R: AsRef<str>, S: Into<Option<Stdio>>>(
        &self,
        command: R,
        stderr: S,
    ) -> anyhow::Result<()> {
        Command::new(&format!("/proc/self/fd/{}", self.nft_file.as_raw_fd()))
            .arg(command.as_ref())
            .stderr(stderr.into().unwrap_or_else(Stdio::inherit))
            .stdout(Stdio::inherit())
            .spawn()?
            .wait()?;

        Ok(())
    }
}
