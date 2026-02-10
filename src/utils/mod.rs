//! A collection of utilities to either:
//!
//! 1. Support the denial of "living off the land" by bundling utilities such as busybox
//! 2. Make development easier for tasks that need to be done quicker
//!
//! Not all commands are going to require the same consistency to run on all systems, and
//! those modules can relax and use the tools from category 2
use eyre::Context;

use std::{fs::OpenOptions, path::Path, process::ExitStatus};

#[cfg(unix)]
pub mod busybox;
pub mod checks;
#[cfg(unix)]
pub mod containers;
#[cfg(unix)]
pub mod download_container;
pub mod logs;
#[cfg(unix)]
pub mod nft;
pub mod os_version;
pub mod pager;
#[cfg(unix)]
pub mod packages;
#[cfg(unix)]
pub mod pamtester;
#[cfg(unix)]
pub mod passwd;
pub mod ports;
#[allow(dead_code)]
pub mod regex;
#[cfg(unix)]
pub mod scheduling;
#[cfg(unix)]
pub mod shell_audit;
#[cfg(unix)]
pub mod ssh;
pub mod system;
#[cfg(unix)]
pub mod systemd;
/// Alias for Perl's qx
///
/// Runs the command provided and returns the output as a string as well as the exit code.
/// Stderr is displayed to the user
///
/// ```
/// # use jj_rs::utils::qx;
/// # fn demo_qx() -> eyre::Result<()> {
/// let os = qx("uname")?.1;
/// assert_eq!(os, "Linux\n");
/// assert_eq!(os.trim(), "Linux");
/// # Ok(())
/// # }
/// # assert!(demo_qx().is_ok());
/// ```
#[cfg(unix)]
pub fn qx(command: &str) -> eyre::Result<(ExitStatus, String)> {
    let output = std::process::Command::new("sh")
        .args(["-c", command])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Alias for Perl's qx
///
/// Runs the command provided and returns the output as a string as well as the exit code.
/// Stderr is displayed to the user
///
/// ```
/// # use jj_rs::utils::qx;
/// # fn demo_qx() -> eyre::Result<()> {
/// let os = qx("uname")?.1;
/// assert_eq!(os, "Linux\n");
/// assert_eq!(os.trim(), "Linux");
/// # Ok(())
/// # }
/// # assert!(demo_qx().is_ok());
/// ```
#[cfg(windows)]
pub fn qx(command: &str) -> eyre::Result<(ExitStatus, String)> {
    let output = std::process::Command::new("cmd")
        .args(["/c", command])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Alias for Perl's qx
///
/// Runs the command provided and returns the output as a string as well as the exit code.
/// Stderr is displayed to the user
/// Runs the commands provided with PowerShell
#[cfg(windows)]
pub fn qxp(command: &str) -> eyre::Result<(ExitStatus, String)> {
    use base64::prelude::*;

    let command = command
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>();

    let output = std::process::Command::new("powershell")
        .args(["-EncodedCommand", &BASE64_STANDARD.encode(command)])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Runs the command provided, inheriting stdin, stdout, and stderr from the shell
///
/// Useful for running one of commands where the operator cares about the result,
/// but not the programmer. Returns only the exit code
///
/// ```
/// # use jj_rs::utils::system;
/// assert!(system("true").unwrap().success());
/// assert!(!system("false").unwrap().success());
/// ```
#[cfg(unix)]
pub fn system(command: &str) -> eyre::Result<ExitStatus> {
    std::process::Command::new("/bin/sh")
        .args(["-c", command])
        .spawn()
        .context("Could not spawn sh")?
        .wait()
        .context("Could not wait for command to finish")
}

/// Runs the command provided, inheriting stdin, stdout, and stderr from the shell
///
/// Useful for running one of commands where the operator cares about the result,
/// but not the programmer. Returns only the exit code
///
/// ```
/// # use jj_rs::utils::system;
/// assert!(system("true").unwrap().success());
/// assert!(!system("false").unwrap().success());
/// ```
#[cfg(windows)]
pub fn system(command: &str) -> eyre::Result<ExitStatus> {
    std::process::Command::new("cmd")
        .args(["/c", command])
        .spawn()
        .context("Could not spawn sh")?
        .wait()
        .context("Could not wait for command to finish")
}

/// Downloads a file to a location, similar to `wget`
///
/// ```no_run
/// # use jj_rs::utils::download_file;
/// # fn demo_download() -> eyre::Result<()> {
/// download_file("https://artifacts.elastic.co/elasticsearch/elasticsearch-9.2.0-amd64.deb", "/tmp/elasticsearch.deb")?;
/// # Ok(())
/// # }
/// ```
pub fn download_file<P: AsRef<Path>>(url: &str, to: P) -> eyre::Result<()> {
    let mut target_file = OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open(to)?;

    let mut response = reqwest::blocking::get(url)?;
    if !response.status().is_success() {
        eyre::bail!(
            "Got response of {} when downloading {url}",
            response.status()
        );
    }

    response.copy_to(&mut target_file)?;

    Ok(())
}
