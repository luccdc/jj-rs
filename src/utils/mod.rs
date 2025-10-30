use anyhow::Context;

use std::{fs::OpenOptions, path::Path, process::ExitStatus};

pub mod busybox;
pub mod distro;
pub mod download_container;
pub mod nft;
pub mod ports;
#[allow(dead_code)]
pub mod regex;

pub fn qx(command: &str) -> anyhow::Result<(ExitStatus, String)> {
    let output = std::process::Command::new("sh")
        .args(&["-c", command])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

pub fn system(command: &str) -> anyhow::Result<ExitStatus> {
    std::process::Command::new("/bin/sh")
        .args(&["-c", command])
        .spawn()
        .context("Could not spawn sh")?
        .wait()
        .context("Could not wait for command to finish")
}

pub fn download_file<P: AsRef<Path>>(url: &str, to: P) -> anyhow::Result<()> {
    let mut target_file = OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open(to)?;
    reqwest::blocking::get(url)?.copy_to(&mut target_file)?;
    Ok(())
}
