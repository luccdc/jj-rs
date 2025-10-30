pub mod busybox;
pub mod distro;
pub mod download_container;
pub mod nft;
pub mod ports;
#[allow(dead_code)]
pub mod regex;

#[allow(dead_code)]
pub fn qx(command: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("sh")
        .args(&["-c", command])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
