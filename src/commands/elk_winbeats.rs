use std::{net::Ipv4Addr, path::PathBuf, process::Command};

use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::utils::download_file;

const FILEBEAT_YML: &str = include_str!("elk/filebeat.windows.yml");
const WINLOGBEAT_YML: &str = include_str!("elk/winlogbeat.windows.yml");
const PACKETBEAT_YML: &str = include_str!("elk/packetbeat.windows.yml");
const METRICBEAT_YML: &str = include_str!("elk/metricbeat.yml");

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
pub struct ElkBeatsArgs {
    /// The IP address of the ELK server to download resources from and send logs to
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    pub elk_ip: Ipv4Addr,

    /// The port of the share on the ELK server
    #[arg(long, short = 'p', default_value_t = 8080)]
    pub elk_share_port: u16,

    /// Where to install and configure all the beats
    #[arg(long, short = 'e', default_value = r"C:\Program Files\Elastic")]
    pub elastic_install_directory: PathBuf,

    /// Path to search for Sysmon. If it's a URL, it will download Sysmon. If it's a zip file, it will search for Sysmon64.exe and extract it. Otherwise, it should be a path to Sysmon64.exe
    #[arg(
        long,
        short = 'P',
        default_value = "https://live.sysinternals.com/Sysmon64.exe"
    )]
    pub sysmon_path: String,

    /// Don't install sysmon. Current configuration logs process executions and network connections
    #[arg(long, short = 'S')]
    pub dont_install_sysmon: bool,
}

#[derive(Subcommand, Debug)]
pub enum ElkCommands {
    /// Install beats and configure the system to send logs to the ELK stack
    #[command(visible_alias = "beats")]
    InstallBeats(ElkBeatsArgs),
}

/// Install, configure, and manage beats locally
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct WinBeats {
    #[command(subcommand)]
    command: ElkCommands,
}

impl super::Command for WinBeats {
    fn execute(self) -> eyre::Result<()> {
        let ElkCommands::InstallBeats(args) = self.command;
        install_winbeats(args, true)
    }
}

pub fn install_winbeats(args: ElkBeatsArgs, enable_powershell_logging: bool) -> eyre::Result<()> {
    println!("{}", "--- Downloading beats...".green());

    std::fs::create_dir_all(&args.elastic_install_directory)?;

    download_file(
        &format!("http://{}:{}/http_ca.crt", args.elk_ip, args.elk_share_port),
        format!("{}\\http_ca.crt", args.elastic_install_directory.display()),
    )?;

    let mut download_threads = vec![];

    for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
        let args = args.clone();
        download_threads.push(std::thread::spawn(move || {
            let res = download_file(
                &format!("http://{}:{}/{beat}.zip", args.elk_ip, args.elk_share_port),
                &format!("{}/{beat}.zip", std::env::temp_dir().display()),
            );
            println!("Done downloading {beat}!");
            res
        }));
    }

    for thread in download_threads {
        match thread.join() {
            Ok(r) => r?,
            Err(_) => {
                eprintln!(
                    "{}",
                    "!!! Could not join download thread due to panic!".red()
                );
            }
        }
    }

    println!("--- Unpacking beats...");

    let mut unpack_threads = vec![];

    for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
        let args = args.clone();
        unpack_threads.push(std::thread::spawn(move || -> eyre::Result<()> {
            let beat_zip = std::io::BufReader::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(std::env::temp_dir().join(&format!("{beat}.zip")))?,
            );
            let mut archive = zip::read::ZipArchive::new(beat_zip)?;

            archive.extract_unwrapped_root_dir(
                args.elastic_install_directory.join(&beat),
                zip::read::root_dir_common_filter,
            )?;

            println!("Unpacked {beat}!");
            Ok(())
        }));
    }

    for thread in unpack_threads {
        match thread.join() {
            Ok(r) => r?,
            Err(_) => {
                eprintln!("{}", "!!! Could not join unpack thread due to panic!".red());
            }
        }
    }

    println!("--- Unpacked beats! Configuring beats...");

    std::fs::write(
        args.elastic_install_directory
            .join("winlogbeat")
            .join("winlogbeat.yml"),
        format!(
            r#"
{WINLOGBEAT_YML}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}\\http_ca.crt"]
"#,
            args.elk_ip,
            format!("{}", args.elastic_install_directory.display()).replace("\\", "\\\\")
        ),
    )?;

    std::fs::write(
        args.elastic_install_directory
            .join("packetbeat")
            .join("packetbeat.yml"),
        format!(
            r#"
{PACKETBEAT_YML}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}\\http_ca.crt"]
"#,
            args.elk_ip,
            format!("{}", args.elastic_install_directory.display()).replace("\\", "\\\\")
        ),
    )?;

    std::fs::write(
        args.elastic_install_directory
            .join("filebeat")
            .join("filebeat.yml"),
        format!(
            r#"
{FILEBEAT_YML}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}\\http_ca.crt"]
"#,
            args.elk_ip,
            format!("{}", args.elastic_install_directory.display()).replace("\\", "\\\\")
        )
        .replace(
            "$FILEBEAT_PATH",
            &format!(
                "{}",
                args.elastic_install_directory.join("filebeat").display()
            ),
        ),
    )?;

    std::fs::write(
        args.elastic_install_directory
            .join("metricbeat")
            .join("metricbeat.yml"),
        format!(
            r#"
{METRICBEAT_YML}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}\\http_ca.crt"]
"#,
            args.elk_ip,
            format!("{}", args.elastic_install_directory.display()).replace("\\", "\\\\")
        )
        .replace(
            "$METRICBEAT_PATH",
            &format!(
                "{}",
                args.elastic_install_directory.join("metricbeat").display()
            ),
        ),
    )?;

    println!("--- Configured beats! Installing as services...");

    for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
        Command::new("powershell.exe")
            .args(&[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &format!(
                    "{}\\{beat}\\install-service-{beat}.ps1",
                    args.elastic_install_directory.display()
                ),
            ])
            .spawn()?
            .wait()?;
    }

    println!("Installing npcap by starting packetbeat... (should fail!)");
    Command::new("sc.exe")
        .args(&["start", "packetbeat"])
        .spawn()?
        .wait()?;

    println!("--- Testing output...");

    for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
        Command::new(format!(
            "{}\\{beat}\\{beat}.exe",
            args.elastic_install_directory.display()
        ))
        .args(&["test", "output"])
        .current_dir(&args.elastic_install_directory.join(beat))
        .spawn()?
        .wait()?;
    }

    println!("--- Starting beats...");

    for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
        Command::new("sc.exe")
            .args(&["start", beat])
            .spawn()?
            .wait()?;
    }

    if enable_powershell_logging {
        enable_scriptblock_logging()?;
    }

    if !args.dont_install_sysmon {
        install_configure_sysmon(args.sysmon_path)?;
    }

    println!("{}", "--- Installed beats!".green());

    Ok(())
}

pub fn enable_scriptblock_logging() -> eyre::Result<()> {
    use windows::{
        Win32::System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey,
            RegCreateKeyExW, RegSetValueExW,
        },
        core::{PCWSTR, Result, w},
    };

    print!("--- Enabling scriptblock logging for PowerShell...");

    unsafe {
        let sub_key = w!(r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
        let value_name = w!("EnableScriptBlockLogging");

        let mut hkey = HKEY::default();

        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()?;

        let value_data = 1u32.to_ne_bytes();

        let result = RegSetValueExW(hkey, value_name, None, REG_DWORD, Some(&value_data)).ok();

        let _ = RegCloseKey(hkey);

        result?;

        println!(" Done");
    }

    Ok(())
}

pub fn install_configure_sysmon(sysmon_path: String) -> eyre::Result<()> {
    let path = if let Ok(p) = reqwest::Url::parse(&sysmon_path)
        && (p.scheme() == "http" || p.scheme() == "https")
    {
        let target_path = std::env::temp_dir().join("Sysmon64.exe");
        crate::utils::download_file(&sysmon_path, &target_path)?;
        target_path
    } else if sysmon_path.ends_with(".zip") {
        let archive =
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&sysmon_path)?);
        let mut archive = zip::read::ZipArchive::new(archive)?;

        let file_name = {
            archive
                .file_names()
                .find(|f| {
                    f.to_ascii_uppercase().ends_with("SYSMON64.EXE")
                        || f.to_ascii_uppercase().ends_with("SYSMON.EXE")
                })
                .ok_or_else(|| eyre::eyre!("Could not find Sysmon64.exe in zip file provided"))?
                .to_owned()
        };

        let target_path = std::env::temp_dir().join("Sysmon64.exe");
        std::io::copy(
            &mut archive.by_name(&file_name)?,
            &mut std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&target_path)?,
        )?;
        target_path
    } else if sysmon_path.ends_with(".exe") {
        PathBuf::from(sysmon_path)
    } else {
        eyre::bail!(
            "Did not provide a valid path to install sysmon from! Expected a URL to download Sysmon, a zip file to search for Sysmon64.exe, or the path to an extracted Sysmon64.exe"
        );
    };

    Command::new(path)
        .args(["-i", "-n", "-l", "-p", "-accepteula"])
        .spawn()?
        .wait()?;

    Ok(())
}
