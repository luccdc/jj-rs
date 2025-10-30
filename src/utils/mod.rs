use std::process::ExitStatus;

pub mod busybox;
pub mod distro;
pub mod download_container;
pub mod nft;
pub mod ports;
#[allow(dead_code)]
pub mod regex;

#[allow(dead_code)]
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
