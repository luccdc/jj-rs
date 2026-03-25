use std::{net::Ipv4Addr, path::PathBuf, process::Command};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::Context;

use crate::utils::download_file;

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

        println!("Waiting for Wazuh service to appear");

        // go to jj-logstash and fix certificate handling. Maybe check if certificates exist
        // then don't generate
        let mut count = 0;
        loop {
            count += 1;
            if count % 10 == 0 {
                println!("Waiting for WazuhSvc to become available...");
            }

            // change to
            let output = Command::new("sc.exe")
                .args(["query", "WazuhSvc"])
                .output()?;

            if !String::from_utf8_lossy(&output.stdout).contains("FAILED") {
                break;
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

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

        super::activatedefender::ShieldsUp.execute()?;

        if !args.dont_install_sysmon {
            super::elk_winbeats::install_configure_sysmon(args.sysmon_path)?;
        }

        if !args.dont_install_clamav {
            super::clamav_windows::install_clamav(args.clamav_url)?;
        }

        Ok(())
    }
}
