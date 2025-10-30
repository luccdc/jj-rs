pub mod busybox;
pub mod download_container;
pub mod nft;

pub fn qx(command: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("sh")
        .args(&["-c", command])
        .stderr(std::process::Stdio::piped())
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
