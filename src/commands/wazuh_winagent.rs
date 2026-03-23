use std::{net::Ipv4Addr, path::PathBuf, process::Command};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::Context;

use crate::utils::download_file;

const CLAMAV_CONF: &str = include_str!("wazuh/clamav.windows.conf");
const FRESHCLAM_CONF: &str = include_str!("wazuh/freshclam.windows.conf");

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
pub struct WazuhAgentsArgs {
    /// The IP address of the Wazuh server to download resources from and send logs to
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    wazuh_ip: Ipv4Addr,

    /// The port of the share on the Wazuh server
    #[arg(long, short = 'p', default_value_t = 8080)]
    wazuh_share_port: u16,

    /// Where to install and configure all the beats, if installed
    #[arg(long, short = 'e', default_value = r"C:\Program Files\Elastic")]
    elastic_install_directory: PathBuf,

    /// Skip installing Beats
    #[arg(long, short = 'B')]
    dont_install_beats: bool,

    /// Path to search for Sysmon. If it's a URL, it will download Sysmon. If it's a zip file, it will search for Sysmon64.exe and extract it. Otherwise, it should be a path to Sysmon64.exe
    #[arg(
        long,
        short = 'P',
        default_value = "https://live.sysinternals.com/Sysmon64.exe"
    )]
    sysmon_path: String,

    /// Don't install sysmon. Current configuration logs process executions and network connections
    #[arg(long, short = 'S')]
    dont_install_sysmon: bool,

    /// URL to download ClamAV from
    #[arg(
        long,
        default_value = "https://www.clamav.net/downloads/production/clamav-1.5.2.win.x64.zip"
    )]
    clamav_url: String,

    /// Don't download and install ClamAV
    #[arg(long, short = 'C')]
    dont_install_clamav: bool,
}

#[derive(Subcommand, Debug)]
pub enum WazuhCommands {
    /// Install agents and potentially beats, configuring them to go to the Wazuh server
    #[command(visible_alias = "agents")]
    InstallAgents(WazuhAgentsArgs),
}

/// Install, configure, and manage Wazuh agents and beats locally
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct WinAgents {
    #[command(subcommand)]
    command: WazuhCommands,
}

impl super::Command for WinAgents {
    fn execute(self) -> eyre::Result<()> {
        let WazuhCommands::InstallAgents(args) = self.command;

        println!("--- Downloading Wazuh agent...");

        let target_file = std::env::temp_dir().join("wazuh-agent.msi");

        download_file(
            &format!(
                "http://{}:{}/wazuh-agent.msi",
                args.wazuh_ip, args.wazuh_share_port
            ),
            &target_file,
        )?;

        println!("Downloaded agent installer! Installing...");

        let hostname = std::env::var("COMPUTERNAME").context("Could not determine host name")?;
        let hostname = hostname.trim();

        Command::new("msiexec.exe")
            .args([
                "-i",
                &*target_file.to_string_lossy(),
                "/q",
                &format!("WAZUH_MANAGER={}", args.wazuh_ip),
                &format!("WAZUH_AGENT_NAME={hostname}"),
            ])
            .spawn()?
            .wait()?;

        println!("Installed! Starting...");

        Command::new("net.exe")
            .args(["start", "Wazuh"])
            .spawn()?
            .wait()?;

        println!("{}", "--- Wazuh agent installed!".green());

        if !args.dont_install_beats {
            super::elk_winbeats::install_winbeats(
                super::elk_winbeats::ElkBeatsArgs {
                    elk_ip: args.wazuh_ip,
                    elk_share_port: args.wazuh_share_port,
                    elastic_install_directory: args.elastic_install_directory,
                    sysmon_path: "".into(),
                    dont_install_sysmon: true,
                },
                false,
            )?;
        }

        super::elk_winbeats::enable_scriptblock_logging()?;

        if !args.dont_install_sysmon {
            super::elk_winbeats::install_configure_sysmon(args.sysmon_path)?;
        }

        if !args.dont_install_clamav {
            install_clamav(args.clamav_url)?;
        }

        Ok(())
    }
}

fn install_clamav(clamav_url: String) -> eyre::Result<()> {
    let working_dir = std::env::temp_dir();
    let target_path = working_dir.join("clamav.zip");
    download_file(&clamav_url, &target_path)?;

    let archive =
        std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(target_path)?);
    let mut archive = zip::read::ZipArchive::new(archive)?;

    archive.extract_unwrapped_root_dir(
        r"C:\Program Files\ClamAV",
        zip::read::root_dir_common_filter,
    )?;

    std::fs::write(r"C:\Program Files\ClamAV\freshclam.conf", FRESHCLAM_CONF)?;
    std::fs::write(r"C:\Program Files\ClamAV\clamav.conf", CLAMAV_CONF)?;

    Command::new(r"C:\Program Files\ClamAV\clamd.exe")
        .arg("--install")
        .current_dir(r"C:\Program Files\ClamAV")
        .spawn()?
        .wait()?;

    Command::new(r"C:\Program Files\ClamAV\freshclam.exe")
        .current_dir(r"C:\Program Files\ClamAV")
        .spawn()?
        .wait()?;

    Command::new("net")
        .args(["start", "clamd"])
        .spawn()?
        .wait()?;

    Ok(())
}
