use std::process::Command;

use crate::utils::download_file;

const CLAMAV_CONF: &str = include_str!("wazuh/clamav.windows.conf");
const FRESHCLAM_CONF: &str = include_str!("wazuh/freshclam.windows.conf");

#[derive(clap::Parser, Debug, Clone)]
pub struct ClamAv {
    /// URL to download ClamAV from
    #[arg(
        long,
        default_value = "https://www.clamav.net/downloads/production/clamav-1.5.2.win.x64.zip"
    )]
    clamav_url: String,
}

impl super::Command for ClamAv {
    fn execute(self) -> eyre::Result<()> {
        println!("--- Installing ClamAV...");
        install_clamav(self.clamav_url)
    }
}

pub fn install_clamav(clamav_url: String) -> eyre::Result<()> {
    if !std::path::PathBuf::from(r"C\Program Files\ClamAV").exists() {
        println!("--- Downloading ClamAV...");
        let working_dir = std::env::temp_dir();
        let target_path = working_dir.join("clamav.zip");
        download_file(&clamav_url, &target_path)?;

        println!("Downloaded ClamAV. Extracting...");
        let archive =
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(target_path)?);
        let mut archive = zip::read::ZipArchive::new(archive)?;

        archive.extract_unwrapped_root_dir(
            r"C:\Program Files\ClamAV",
            zip::read::root_dir_common_filter,
        )?;

        println!("--- Extraction complete; configuring ClamAV");
    } else {
        println!(
            "--- ClamAV already downloaded and extracted! Run `jj clam-av -O` to override, and make sure that ClamAV isn't running"
        );
    }

    std::fs::write(r"C:\Program Files\ClamAV\freshclam.conf", FRESHCLAM_CONF)?;
    std::fs::write(r"C:\Program Files\ClamAV\clamd.conf", CLAMAV_CONF)?;

    Command::new(r"C:\Program Files\ClamAV\clamd.exe")
        .arg("--install")
        .current_dir(r"C:\Program Files\ClamAV")
        .spawn()?
        .wait()?;

    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Invoke-WebRequest -Uri 'https://database.clamav.net/daily.cvd' -Method HEAD",
        ])
        .output()?;

    println!("--- Downloading ClamAV definitions");

    Command::new(r"C:\Program Files\ClamAV\freshclam.exe")
        .current_dir(r"C:\Program Files\ClamAV")
        .spawn()?
        .wait()?;

    println!("--- Starting ClamAV!");

    Command::new("net")
        .args(["start", "clamd"])
        .spawn()?
        .wait()?;

    Ok(())
}
