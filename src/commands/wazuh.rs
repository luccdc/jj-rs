use std::{
    fs::Permissions,
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::fs::{PermissionsExt, chown},
    path::PathBuf,
    process::{Command, Stdio},
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::Context;
use libc::getuid;

use crate::{
    pcre,
    utils::{
        busybox::Busybox,
        download_container::DownloadContainer,
        download_file, get_public_ip,
        os_version::{Distro, get_distro},
        packages::{install_apt_packages, install_dnf_packages},
        passwd, qx, system,
    },
};

// Defines a variable called WAZUH_DASHBOARDS of type &'static [&'static str]
// It includes all the ndjson files for wazuh dashboards
include!(concat!(env!("OUT_DIR"), "/wazuh_dashboards.rs"));

const LOGSTASH_WAZUH_CONF: &str = include_str!("elk/pipeline-wazuh.conf");

#[derive(Parser, Debug)]
#[command(about)]
pub struct WazuhSubcommandArgs {
    /// Version to use for Wazuh to download packages and install them
    #[arg(long, short = 'V', default_value = "4.14")]
    pub wazuh_version: String,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    pub use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,

    /// Install Logstash and download beats, but configure Logstash only to point towards Wazuh's opensearch. This will also attempt to set up all the ingest pipelines, index templates, and data views used by beats. This option will enable the Wazuh server to act like an ELK 9 compliant server
    #[arg(long, short = 'i')]
    pub independent_logstash_install: bool,

    /// Where will temporary files be downloaded and extracted
    #[arg(long, short = 'w', default_value = "/tmp/wazuh-working-dir")]
    pub working_dir: PathBuf,

    /// Where to look for a jiujitsu installation of ELK when importing data and configurations
    #[arg(long, short = 'e', default_value = "/opt/jj-es")]
    pub jj_elastic_location: PathBuf,

    /// Where to look for the share drive for jiujitsu ELK installation, specifically to place the Wazuh CA certificate for Logstash
    #[arg(long, short = 'E', default_value = "/opt/es-share")]
    pub jj_elastic_share_location: PathBuf,

    /// The version of ELK that this Wazuh setup is being designed to cooperate with
    #[arg(long, short = 'S', default_value = "9.3.0")]
    pub jj_elastic_version: String,

    /// URL to download Logstash from; used when setting up independent logstash
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads")]
    pub download_url: String,

    /// URL to download Auditbeat, Filebeat, Packetbeat, Metricbeat, and Winlogbeat from; used when setting up independent logstash
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads/beats")]
    pub beats_download_url: String,

    /// Public NAT IP for Wazuh and Logstash
    #[arg(long, short = 'N')]
    pub public_nat_ip: Option<Ipv4Addr>,

    /// Don't install Suricata when installing beats
    #[arg(long, short = 's')]
    pub dont_install_suricata: bool,

    /// Wazuh doesn't have the same performance hacks as Elasticsearch; tweak the ceiling for script compilations
    #[arg(long, short = 'M', default_value = "10000")]
    pub max_compilations_rate: u32,
}

#[derive(Parser, Debug)]
#[command(about)]
pub struct WazuhAgentCommandArgs {
    /// The IP address of the Wazuh server to download resources from and send logs to
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    wazuh_ip: Ipv4Addr,

    /// The port of the share on the Wazuh server to download agents from
    #[arg(long, short = 'p', default_value_t = 8080)]
    wazuh_share_port: u16,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,

    /// Where to install and configure all the beats
    #[arg(long, short = 'e', default_value = "/opt/jj-es")]
    elastic_install_directory: PathBuf,

    /// Don't install beats alongside Wazuh agent
    #[arg(long, short = 'B')]
    dont_install_beats: bool,

    /// Don't install Suricata alongside beats and agent
    #[arg(long, short = 'S')]
    dont_install_suricata: bool,
}

#[derive(Subcommand, Debug)]
pub enum WazuhCommands {
    /// Install Wazuh completely
    #[command(visible_alias = "in")]
    Install(WazuhSubcommandArgs),

    /// Setup ZRAM to provide 4G of swap based on compressed RAM
    #[command(visible_alias = "zr")]
    SetupZram,

    /// Make working directory for later steps
    #[command(visible_alias = "mw")]
    MakeWorkingDirectory(WazuhSubcommandArgs),

    /// Download the install script, config file, and packages
    #[command(visible_alias = "dl")]
    DownloadFiles(WazuhSubcommandArgs),

    /// Generate offline bundle and certificates
    #[command(visible_alias = "gen")]
    GenerateBundle(WazuhSubcommandArgs),

    /// Unpack the generated bundle
    #[command(visible_alias = "unp")]
    UnpackBundle(WazuhSubcommandArgs),

    /// Install and configure the Wazuh indexer
    #[command(visible_alias = "ii")]
    InstallIndexer(WazuhSubcommandArgs),

    /// Install and configure the Wazuh server
    #[command(visible_alias = "is")]
    InstallServer(WazuhSubcommandArgs),

    /// Install and configure Wazuh filebeat
    #[command(visible_alias = "if")]
    InstallFilebeat(WazuhSubcommandArgs),

    /// Install and configure the Wazuh dashboard
    #[command(visible_alias = "id")]
    InstallDashboard(WazuhSubcommandArgs),

    /// Rotate credentials and prompt for the password to set the admin user to use
    #[command(visible_alias = "rc")]
    RotateCredentials,

    /// Import beats ingest pipelines from an ELK stack installed by jiujitsu running on the same system
    #[command(visible_alias = "ip")]
    ImportPipelines(WazuhSubcommandArgs),

    /// Configure jj-logstash to install the opensearch output plugin and copy data to Wazuh's opensearch instance. If `independent-logstash-install` is specified, this will install logstash configured only to point to Wazuh
    #[command(visible_alias = "fl")]
    ForwardJjLogstash(WazuhSubcommandArgs),

    /// Install jj beats to forward to local logstash. Only works when `independent-logstash-install` explicitly set
    #[command(visible_alias = "ib")]
    InstallBeats(WazuhSubcommandArgs),

    /// Load built in JJ dashboards to Wazuh
    #[command(visible_alias = "wb")]
    LoadWazuhDashboards,

    /// Tweak the max script compilation rate that Wazuh uses
    #[command(visible_alias = "ts")]
    TweakSctiptCompilationLimit(WazuhSubcommandArgs),

    /// Install and configure agents and beats on an endpoint
    #[command(visible_alias = "agents")]
    InstallAgents(WazuhAgentCommandArgs),
}

/// Install, configure, and manage Wazuh on this server
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Wazuh {
    #[command(subcommand)]
    pub command: WazuhCommands,
}

impl super::Command for Wazuh {
    fn execute(self) -> eyre::Result<()> {
        if unsafe { getuid() } != 0 {
            eprintln!("{}", "!!! This script requires you to run as root".red());
            return Ok(());
        }

        use WazuhCommands as WC;

        let distro = get_distro()?;

        if !distro.is_rhel_or_deb_based() {
            eprintln!(
                "{}",
                "!!! Wazuh utilities can only be run on RHEL or Debian".red()
            );
            return Ok(());
        }

        let busybox = Busybox::new()?;

        if let WC::InstallAgents(args) = &self.command {
            return install_agents(&busybox, &distro, args);
        }

        let hostname = qx("hostnamectl")?.1;
        if pcre!(&hostname =~ qr/r"Static\+hostname:\s\(unset\)"/xms) {
            eprintln!(
                "{}",
                "!!! Wazuh installation requires a hostname explicitly set".red()
            );
            return Ok(());
        }

        let mut new_pass = String::new();

        if let WC::Install(_)
        | WC::RotateCredentials
        | WC::ImportPipelines(_)
        | WC::ForwardJjLogstash(_)
        | WC::LoadWazuhDashboards
        | WC::TweakSctiptCompilationLimit(_) = &self.command
        {
            const PASSWORD_RULES: &[fn(&str) -> bool] = &[
                |s| s.len() > 8 && s.len() < 64,
                |s| s.chars().any(char::is_uppercase),
                |s| s.chars().any(char::is_lowercase),
                |s| s.chars().any(char::is_numeric),
                |s| s.contains(|c| matches!(c, '.' | '*' | '+' | '?' | '-')),
            ];

            loop {
                if !new_pass.is_empty() {
                    println!(
                        "Password must have a length between 8 and 64 characters and contain at least one upper and lower case letter, a letter and a symbol(.*+?-)"
                    );
                }

                print!("Enter the password for the admin user: ");
                std::io::stdout()
                    .flush()
                    .context("Could not display password prompt")?;
                std::io::stdin()
                    .read_line(&mut new_pass)
                    .context("Could not read password from user")?;
                new_pass = new_pass.trim().to_string();

                if PASSWORD_RULES.iter().all(|rule| (rule)(&new_pass)) {
                    break;
                }
            }
        }

        let mut elastic_pass = String::new();

        if let WC::Install(args) | WC::ImportPipelines(args) = &self.command {
            if !args.independent_logstash_install {
                print!("Enter the password for the Elastic user (leave empty if not installed): ");
                std::io::stdout()
                    .flush()
                    .context("Could not display password prompt")?;
                std::io::stdin()
                    .read_line(&mut elastic_pass)
                    .context("Could not read password from user")?;
                elastic_pass = elastic_pass.trim().to_string();
            }
        }

        self.execute_pipeline(&distro, &busybox, &new_pass, &elastic_pass)
    }
}

impl Wazuh {
    pub fn execute_pipeline(
        self,
        distro: &Distro,
        busybox: &Busybox,
        new_pass: &str,
        elastic_pass: &str,
    ) -> eyre::Result<()> {
        use WazuhCommands as WC;

        if let WC::Install(_) | WC::SetupZram = &self.command
            && let Err(e) = setup_zram()
        {
            eprintln!("{}{e}", "??? Could not set up zram: ".yellow());
        }

        if let WC::Install(args) | WC::MakeWorkingDirectory(args) = &self.command {
            make_working_dirs(&args)?;
        }

        if let WC::Install(args) | WC::DownloadFiles(args) = &self.command {
            download_files(&args, distro)?;
        }

        if let WC::Install(args) | WC::GenerateBundle(args) = &self.command {
            generate_bundle(&args, busybox)?;
        }

        if let WC::Install(args) | WC::UnpackBundle(args) = &self.command {
            unpack_bundle(&args, busybox)?;
        }

        if let WC::Install(args) | WC::InstallIndexer(args) = &self.command {
            install_indexer(&args, distro)?;
        }

        if let WC::Install(args) | WC::InstallServer(args) = &self.command {
            install_server(&args, distro)?;
        }

        if let WC::Install(args) | WC::InstallFilebeat(args) = &self.command {
            install_filebeat(&args, distro, busybox)?;
        }

        if let WC::Install(args) | WC::InstallDashboard(args) = &self.command {
            install_dashboard(&args, distro, busybox)?;
        }

        if let WC::Install(_) | WC::RotateCredentials = &self.command {
            rotate_credentials(busybox, new_pass)?;
        }

        if let WC::Install(args) | WC::ImportPipelines(args) = &self.command {
            if !args.independent_logstash_install {
                import_pipelines(busybox, args, new_pass, elastic_pass)?;
            } else {
                import_direct_from_beats(busybox, args, new_pass)?;
            }
        }

        if let WC::Install(args) | WC::ForwardJjLogstash(args) = &self.command {
            if args.independent_logstash_install {
                install_jj_logstash(busybox, args)?;
            }
            forward_jj_logstash(busybox, args, new_pass)?;
        }

        if let WC::Install(args) = &self.command
            && args.independent_logstash_install
        {
            install_beats(busybox, args)?;
        }

        if let WC::InstallBeats(args) = &self.command {
            install_beats(busybox, args)?;
        }

        if let WC::Install(_) | WC::LoadWazuhDashboards = &self.command {
            load_wazuh_dashboards(busybox, new_pass)?;
        }

        if let WC::TweakSctiptCompilationLimit(args) = &self.command {
            tweak_max_compilations_rate(busybox, new_pass, args.max_compilations_rate)?;
        }

        if let WC::Install(args) = &self.command {
            cleanup(&args)?;
        }

        Ok(())
    }
}

fn setup_zram() -> eyre::Result<()> {
    let mods = qx("lsmod")?.1;

    if pcre!(&mods =~ qr/"zram"/xms) {
        println!("{}", "--- Skipping ZRAM setup (already loaded)".green());
        return Ok(());
    }

    if !qx("modprobe zram")?.0.success() {
        eyre::bail!("Could not load zram!");
    }

    if !qx("zramctl /dev/zram0 --size=4G")?.0.success() {
        eyre::bail!("Could not initialize zram device");
    }

    if !qx("mkswap /dev/zram0")?.0.success() {
        eyre::bail!("Could not initialize zram swap space");
    }

    if !qx("swapon --priority=100 /dev/zram0")?.0.success() {
        eyre::bail!("Could not enable zram swap space");
    }

    println!("{}", "--- ZRAM has been set up!".green());

    Ok(())
}

fn make_working_dirs(args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    std::fs::create_dir_all(&args.working_dir)?;

    if args.independent_logstash_install {
        std::fs::create_dir_all(&args.jj_elastic_location)?;
    }

    // Piggyback off of the share location to also store agent installers
    std::fs::create_dir_all(&args.jj_elastic_share_location)?;

    println!("{}", "--- Working directory made".green());

    Ok(())
}

fn download_files(args: &WazuhSubcommandArgs, os: &Distro) -> eyre::Result<()> {
    println!("--- Downloading installer and packages...");

    let download_files_internal = || -> eyre::Result<()> {
        use crate::utils::download_file;

        let mut installer_path = args.working_dir.clone();
        installer_path.push("wazuh-install.sh");
        download_file(
            &format!(
                "https://packages.wazuh.com/{}/wazuh-install.sh",
                &args.wazuh_version
            ),
            &installer_path,
        )?;

        std::fs::set_permissions(
            format!("{}/wazuh-install.sh", &args.working_dir.display()),
            PermissionsExt::from_mode(0o755),
        )?;

        let (pkg_type, arch_type) = if os.is_deb_based() {
            ("deb", "amd64")
        } else {
            ("rpm", "x86_64")
        };

        Command::new("/bin/sh")
            .args([
                "-c",
                &format!("./wazuh-install.sh -dw {pkg_type} -da {arch_type}"),
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh")?
            .wait()
            .context("Could not wait for command to finish")?;

        println!("--- Done running download script, downloading agent installers");

        let gzip = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .read(true)
                .open(args.working_dir.join("wazuh-offline.tar.gz"))?,
        );
        let mut archive = tar::Archive::new(flate2::bufread::GzDecoder::new(gzip));
        let wazuh_package_full = archive
            .entries()?
            .find_map(|e| {
                e.as_ref().ok().and_then(|e| {
                    e.path()
                        .ok()
                        .and_then(|p| p.file_name().and_then(|p| p.to_str()).map(str::to_string))
                        .filter(|p| p.starts_with("wazuh-manager"))
                })
            })
            .ok_or_else(|| {
                eyre::eyre!("Could not find wazuh-manager package to determine version")
            })?;

        let version_regex =
            regex::Regex::new(r"wazuh-manager[-_]([-_.0-9]+)(_amd64\.deb|\.x86_64\.rpm)")
                .expect("static regex testing failed");

        let (_, [wazuh_version, _]) = version_regex
            .captures(&wazuh_package_full)
            .ok_or_else(|| eyre::eyre!("Could not match wazuh manager package to extract version"))?
            .extract();

        let Some(major_version) = wazuh_version.chars().next() else {
            eyre::bail!("Wazuh version matched is an empty string!");
        };

        println!("Downloading for version {wazuh_version}");

        let mut download_threads = vec![];
        for (file_name, url) in [
            (
                "wazuh-agent.msi",
                format!(
                    "https://packages.wazuh.com/{major_version}.x/windows/wazuh-agent-{wazuh_version}.msi"
                ),
            ),
            (
                "wazuh-agent.rpm",
                format!(
                    "https://packages.wazuh.com/{major_version}.x/yum/wazuh-agent-{wazuh_version}.x86_64.rpm"
                ),
            ),
            (
                "wazuh-agent.deb",
                format!(
                    "https://packages.wazuh.com/{major_version}.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}_amd64.deb"
                ),
            ),
        ] {
            let download_package = {
                let mut dest_path = args.jj_elastic_share_location.clone();
                move || {
                    dest_path.push(&file_name);
                    let res = download_file(&url, dest_path);
                    println!("Done downloading {file_name}");
                    res
                }
            };

            if args.use_download_shell {
                download_package()?;
            } else {
                download_threads.push(std::thread::spawn(download_package));
            }
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

        println!("{}", "--- Successfully downloaded Wazuh files!".green());

        if args.independent_logstash_install {
            println!("--- Downloading ELK packages... (Logstash + beats)");

            let mut download_threads = vec![];

            let download_package = {
                let mut dest_path = args.jj_elastic_share_location.clone();
                let url = format!(
                    "{}/logstash/logstash-{}-linux-x86_64.tar.gz",
                    args.download_url, args.jj_elastic_version
                );
                move || {
                    dest_path.push(format!("logstash.tar.gz"));
                    let res = download_file(&url, dest_path);
                    println!("Done downloading logstash!");
                    res
                }
            };
            if args.use_download_shell {
                download_package()?;
            } else {
                download_threads.push(std::thread::spawn(download_package));
            }

            for beat in ["auditbeat", "filebeat", "packetbeat", "metricbeat"] {
                let download_package = {
                    let url = format!(
                        "{}/{}/{}-{}-linux-x86_64.tar.gz",
                        args.beats_download_url, beat, beat, args.jj_elastic_version
                    );
                    let mut dest_path = args.jj_elastic_share_location.clone();
                    let beat = beat.to_string();

                    move || {
                        dest_path.push(format!("{beat}.tar.gz"));
                        let res = download_file(&url, dest_path);
                        println!("Done downloading {beat} for Linux!");
                        res
                    }
                };
                if args.use_download_shell {
                    download_package()?;
                } else {
                    download_threads.push(std::thread::spawn(download_package));
                }
            }

            for beat in ["winlogbeat", "filebeat", "packetbeat", "metricbeat"] {
                let download_package = {
                    let mut dest_path = args.jj_elastic_share_location.clone();
                    let url = format!(
                        "{}/{}/{}-{}-windows-x86_64.zip",
                        args.beats_download_url, beat, beat, args.jj_elastic_version
                    );
                    let beat = beat.to_string();

                    move || {
                        dest_path.push(format!("{beat}.zip"));
                        let res = download_file(&url, dest_path);
                        println!("Done downloading {beat} for Windows!");
                        res
                    }
                };
                if args.use_download_shell {
                    download_package()?;
                } else {
                    download_threads.push(std::thread::spawn(download_package));
                }
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

            println!("{}", "--- Successfully downloaded ELK packages!".green());
        }

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(download_files_internal)??;
    } else {
        download_files_internal()?;
    }

    Ok(())
}

fn generate_bundle(args: &WazuhSubcommandArgs, bb: &Busybox) -> eyre::Result<()> {
    println!("--- Generating Wazuh bundle...");

    let public_ip = get_public_ip(bb)?;

    let mut config_yml = args.working_dir.to_owned();
    config_yml.push("config.yml");
    std::fs::write(
        config_yml,
        format!(
            r#"nodes:
  indexer:
    - name: node-1
      ip: "{public_ip}"
  server:
    - name: wazuh-1
      ip: "{public_ip}"
  dashboard:
    - name: dashboard
      ip: "{public_ip}"
"#
        ),
    )?;

    Command::new("/bin/sh")
        .args(["-c", "./wazuh-install.sh -g"])
        .current_dir(&args.working_dir)
        .spawn()
        .context("Could not spawn sh")?
        .wait()
        .context("Could not wait for command to finish")?;

    println!("{}", "--- Successfully generated Wazuh bundle!".green());

    Ok(())
}

fn unpack_bundle(args: &WazuhSubcommandArgs, bb: &Busybox) -> eyre::Result<()> {
    println!("--- Unpacking generated Wazuh bundle...");

    bb.command("tar")
        .args(["xf", "wazuh-offline.tar.gz"])
        .current_dir(&args.working_dir)
        .spawn()
        .context("Could not spawn tar")?
        .wait()
        .context("Could not wait for tar to finish")?;

    std::fs::remove_file(args.working_dir.join("wazuh-offline.tar.gz"))?;

    bb.command("tar")
        .args(["xf", "wazuh-install-files.tar"])
        .current_dir(&args.working_dir)
        .spawn()
        .context("Could not spawn tar")?
        .wait()
        .context("Could not wait for tar to finish")?;

    std::fs::remove_file(args.working_dir.join("wazuh-install-files.tar"))?;

    println!("{}", "--- Unpacked Wazuh bundle!".green());

    Ok(())
}

fn install_indexer(args: &WazuhSubcommandArgs, distro: &Distro) -> eyre::Result<()> {
    println!("--- Installing Wazuh indexer");

    let settings = if args.use_download_shell {
        crate::utils::packages::DownloadSettings::Container {
            name: None,
            sneaky_ip: args.sneaky_ip,
        }
    } else {
        crate::utils::packages::DownloadSettings::NoContainer
    };

    if distro.is_deb_based() {
        install_apt_packages(settings, &["debconf", "adduser", "procps"])?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    } else {
        install_dnf_packages(settings, &["coreutils"])?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to import the Wazuh key")?
            .wait()
            .context("Could not wait for RPM to finish importing the Wazuh key")?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    }

    std::fs::create_dir_all("/etc/wazuh-indexer/certs")?;

    let mut wazuh_install_files = args.working_dir.to_path_buf();
    wazuh_install_files.push("wazuh-install-files");

    let mut node_1_pem = wazuh_install_files.clone();
    node_1_pem.push("node-1.pem");
    std::fs::rename(node_1_pem, "/etc/wazuh-indexer/certs/indexer.pem")?;

    let mut node_1_key = wazuh_install_files.clone();
    node_1_key.push("node-1-key.pem");
    std::fs::rename(node_1_key, "/etc/wazuh-indexer/certs/indexer-key.pem")?;

    let mut admin_key = wazuh_install_files.clone();
    admin_key.push("admin-key.pem");
    std::fs::rename(admin_key, "/etc/wazuh-indexer/certs/admin-key.pem")?;

    let mut admin_pem = wazuh_install_files.clone();
    admin_pem.push("admin.pem");
    std::fs::rename(admin_pem, "/etc/wazuh-indexer/certs/admin.pem")?;

    let mut root_ca = wazuh_install_files.clone();
    root_ca.push("root-ca.pem");
    std::fs::copy(root_ca, "/etc/wazuh-indexer/certs/root-ca.pem")?;

    std::fs::set_permissions("/etc/wazuh-indexer/certs", PermissionsExt::from_mode(0o500))?;

    let wazuh_indexer_user = passwd::load_users("wazuh-indexer")
        .ok()
        .and_then(|v| v.into_iter().next());
    let wazuh_indexer_group = passwd::load_groups("wazuh-indexer")
        .ok()
        .and_then(|v| v.into_iter().next());

    for file in [
        "root-ca.pem",
        "admin.pem",
        "admin-key.pem",
        "indexer-key.pem",
        "indexer.pem",
    ] {
        std::fs::set_permissions(
            format!("/etc/wazuh-indexer/certs/{file}"),
            PermissionsExt::from_mode(0o400),
        )?;

        chown(
            format!("/etc/wazuh-indexer/certs/{file}"),
            wazuh_indexer_user.as_ref().map(|u| u.uid),
            wazuh_indexer_group.as_ref().map(|g| g.gid),
        )?;
    }

    chown(
        format!("/etc/wazuh-indexer/certs/"),
        wazuh_indexer_user.as_ref().map(|u| u.uid),
        wazuh_indexer_group.as_ref().map(|g| g.gid),
    )?;

    system("systemctl daemon-reload")?;
    system("systemctl enable wazuh-indexer")?;
    system("systemctl start wazuh-indexer")?;

    system("/usr/share/wazuh-indexer/bin/indexer-security-init.sh")?;

    println!("--- Sanity check to ensure indexer is set up:");

    let client = reqwest::blocking::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    const WAZUH_AUTH_ATTEMPT_COUNT: i32 = 15;
    for i in 0..=WAZUH_AUTH_ATTEMPT_COUNT {
        if i == WAZUH_AUTH_ATTEMPT_COUNT {
            eyre::bail!("Wazuh indexer security did not successfully start!");
        }

        let resp = client
            .get("https://127.0.0.1:9200")
            .basic_auth("admin", Some("admin"))
            .send()?;

        if resp.status() == 200 {
            println!("Successful response: {}", resp.text()?);
            break;
        }

        println!(
            "Attempt {}: Received status code of {}, waiting 3 seconds...",
            i + 1,
            resp.status()
        );
        println!("{}", resp.text()?);

        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    println!("{}", "--- Wazuh indexer set up!".green());

    Ok(())
}

fn install_server(args: &WazuhSubcommandArgs, distro: &Distro) -> eyre::Result<()> {
    println!("--- Installing Wazuh server");

    if distro.is_deb_based() {
        let settings = if args.use_download_shell {
            crate::utils::packages::DownloadSettings::Container {
                name: None,
                sneaky_ip: args.sneaky_ip,
            }
        } else {
            crate::utils::packages::DownloadSettings::NoContainer
        };

        install_apt_packages(settings, &["gnupg", "apt-transport-https"])?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    } else {
        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to import the Wazuh key")?
            .wait()
            .context("Could not wait for RPM to finish importing the Wazuh key")?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    }

    let mut set_wazuh_username = Command::new("/var/ossec/bin/wazuh-keystore")
        .args(["-f", "indexer", "-k", "username"])
        .stdin(Stdio::piped())
        .spawn()
        .context("Could not start wazuh keystore to store username")?;
    let mut stdin = set_wazuh_username.stdin.take().ok_or(eyre::eyre!(
        "Could not acquire handle to wazuh keystore stdin to send username"
    ))?;
    stdin
        .write_all(b"admin\n")
        .context("Could not write username to stdin")?;
    set_wazuh_username
        .wait()
        .context("Could not wait for username to be set")?;

    let mut set_wazuh_password = Command::new("/var/ossec/bin/wazuh-keystore")
        .args(["-f", "indexer", "-k", "password"])
        .stdin(Stdio::piped())
        .spawn()
        .context("Could not start wazuh keystore to store password")?;
    let mut stdin = set_wazuh_password.stdin.take().ok_or(eyre::eyre!(
        "Could not acquire handle to wazuh keystore stdin to send password"
    ))?;
    stdin
        .write_all(b"admin\n")
        .context("Could not write password to stdin")?;
    set_wazuh_password
        .wait()
        .context("Could not wait for password to be set")?;

    system("systemctl daemon-reload")?;
    system("systemctl enable wazuh-manager")?;
    system("systemctl start wazuh-manager")?;

    println!("{}", "--- Installed Wazuh server manager".green());

    Ok(())
}

fn install_filebeat(args: &WazuhSubcommandArgs, distro: &Distro, bb: &Busybox) -> eyre::Result<()> {
    use serde_yaml_ng::Value;

    println!("--- Installing Wazuh filebeat");

    if distro.is_deb_based() {
        Command::new("/bin/sh")
            .args(["-c", "dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb"])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    } else {
        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to import the Wazuh key")?
            .wait()
            .context("Could not wait for RPM to finish importing the Wazuh key")?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm -ivh ./wazuh-offline/wazuh-packages/filebeat*.rpm",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    }

    let mut wazuh_files = args.working_dir.to_path_buf();
    wazuh_files.push("wazuh-offline");
    wazuh_files.push("wazuh-files");

    let mut filebeat_yml = wazuh_files.clone();
    filebeat_yml.push("filebeat.yml");
    std::fs::copy(&filebeat_yml, "/etc/filebeat/filebeat.yml")?;
    std::fs::copy(filebeat_yml, "/etc/filebeat/filebeat.yml.bak")?;

    let mut wazuh_template = wazuh_files.clone();
    wazuh_template.push("wazuh-template.json");
    std::fs::copy(wazuh_template, "/etc/filebeat/wazuh-template.json")?;

    let mut wazuh_template_perms =
        std::fs::metadata("/etc/filebeat/wazuh-template.json")?.permissions();
    wazuh_template_perms.set_mode(wazuh_template_perms.mode() | 0o011);
    std::fs::set_permissions("/etc/filebeat/wazuh-template.json", wazuh_template_perms)?;

    system("filebeat keystore create")?;

    system("echo admin | filebeat keystore add username --stdin --force")?;
    system("echo admin | filebeat keystore add password --stdin --force")?;

    bb.command("tar")
        .args([
            "-xzf",
            "./wazuh-offline/wazuh-files/wazuh-filebeat-0.5.tar.gz",
            "-C",
            "/usr/share/filebeat/module",
        ])
        .current_dir(&args.working_dir)
        .spawn()
        .context("Could not spawn tar to extract the wazuh filebeat module")?
        .wait()
        .context("Could not wait for tar to finish extracting wazuh filebeat module")?;

    std::fs::create_dir_all("/etc/filebeat/certs")?;

    let mut wazuh_install_files = args.working_dir.to_path_buf();
    wazuh_install_files.push("wazuh-install-files");

    let mut wazuh_1_pem = wazuh_install_files.clone();
    wazuh_1_pem.push("wazuh-1.pem");
    std::fs::rename(wazuh_1_pem, "/etc/filebeat/certs/filebeat.pem")?;

    let mut wazuh_1_key = wazuh_install_files.clone();
    wazuh_1_key.push("wazuh-1-key.pem");
    std::fs::rename(wazuh_1_key, "/etc/filebeat/certs/filebeat-key.pem")?;

    let mut root_ca = wazuh_install_files.clone();
    root_ca.push("root-ca.pem");
    std::fs::copy(root_ca, "/etc/filebeat/certs/root-ca.pem")?;

    std::fs::set_permissions("/etc/filebeat/certs", PermissionsExt::from_mode(0o500))?;

    for file in ["root-ca.pem", "filebeat-key.pem", "filebeat.pem"] {
        std::fs::set_permissions(
            format!("/etc/filebeat/certs/{file}"),
            PermissionsExt::from_mode(0o400),
        )?;

        chown(format!("/etc/filebeat/certs/{file}"), Some(0), Some(0))?;
    }

    chown("/etc/filebeat/certs/", Some(0), Some(0))?;

    let public_ip = get_public_ip(bb)?;

    let filebeat_config = std::fs::read_to_string("/etc/filebeat/filebeat.yml")
        .context("Could not read filebeat configuration")?;

    let mut filebeat_config = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&filebeat_config)
        .context("Could not parse filebeat configuration")?;

    if !args.independent_logstash_install
        && let Value::Mapping(top) = &mut filebeat_config
        && let Some(Value::Sequence(modules)) = top.get_mut("filebeat.modules")
        && let Some(Value::Mapping(wazuh)) = modules.get_mut(0)
        && let Some(Value::Mapping(archives)) = wazuh.get_mut("archives")
    {
        archives.insert("enabled".into(), true.into());
    }

    if let Value::Mapping(top) = &mut filebeat_config
        && let Some(Value::Mapping(elasticsearch)) = top.get_mut("output.elasticsearch")
    {
        elasticsearch.insert(
            "hosts".into(),
            (&[Value::String(format!("{public_ip}:9200"))][..]).into(),
        );
    }

    std::fs::write(
        "/etc/filebeat/filebeat.yml",
        serde_yaml_ng::to_string(&filebeat_config)
            .context("Could not serialize filebeat configuration")?,
    )
    .context("Could not save filebeat configuration")?;

    system("systemctl daemon-reload")?;
    system("systemctl enable filebeat")?;
    system("systemctl start filebeat")?;

    system("filebeat test output")?;

    println!(
        "{}",
        "--- Filebeat successfully installed and configured!".green()
    );

    Ok(())
}

fn install_dashboard(
    args: &WazuhSubcommandArgs,
    distro: &Distro,
    bb: &Busybox,
) -> eyre::Result<()> {
    use serde_yaml_ng::Value;

    println!("--- Installing and configuring wazuh dashboards");

    let settings = if args.use_download_shell {
        crate::utils::packages::DownloadSettings::Container {
            name: None,
            sneaky_ip: args.sneaky_ip,
        }
    } else {
        crate::utils::packages::DownloadSettings::NoContainer
    };

    if distro.is_deb_based() {
        install_apt_packages(settings, &["debhelper", "tar", "curl", "libcap2-bin"])?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    } else {
        install_dnf_packages(settings, &["libcap"])
            .context("Could not install libcap for dashboards")?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to import the Wazuh key")?
            .wait()
            .context("Could not wait for RPM to finish importing the Wazuh key")?;

        Command::new("/bin/sh")
            .args([
                "-c",
                "rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm",
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh to install Wazuh indexer")?
            .wait()
            .context("Could not wait for RPM to install Wazuh indexer")?;
    }

    let mut wazuh_files = args.working_dir.to_path_buf();
    wazuh_files.push("wazuh-install-files");

    std::fs::create_dir_all("/etc/wazuh-dashboard/certs")?;

    let mut dashboard_pem = wazuh_files.clone();
    dashboard_pem.push("dashboard.pem");
    std::fs::rename(dashboard_pem, "/etc/wazuh-dashboard/certs/dashboard.pem")?;

    let mut dashboard_key = wazuh_files.clone();
    dashboard_key.push("dashboard-key.pem");
    std::fs::rename(
        dashboard_key,
        "/etc/wazuh-dashboard/certs/dashboard-key.pem",
    )?;

    let mut root_ca_pem = wazuh_files.clone();
    root_ca_pem.push("root-ca.pem");
    std::fs::copy(root_ca_pem, "/etc/wazuh-dashboard/certs/root-ca.pem")?;

    let wazuh_dashboard_user = passwd::load_users("wazuh-dashboard")
        .ok()
        .and_then(|v| v.into_iter().next());
    let wazuh_dashboard_group = passwd::load_groups("wazuh-dashboard")
        .ok()
        .and_then(|v| v.into_iter().next());

    std::fs::set_permissions(
        "/etc/wazuh-dashboard/certs",
        PermissionsExt::from_mode(0o500),
    )?;

    chown(
        "/etc/wazuh-dashboard/certs",
        wazuh_dashboard_user.as_ref().map(|u| u.uid),
        wazuh_dashboard_group.as_ref().map(|g| g.gid),
    )?;

    for file in ["dashboard.pem", "dashboard-key.pem", "root-ca.pem"] {
        std::fs::set_permissions(
            format!("/etc/wazuh-dashboard/certs/{file}"),
            PermissionsExt::from_mode(0o500),
        )?;

        chown(
            format!("/etc/wazuh-dashboard/certs/{file}"),
            wazuh_dashboard_user.as_ref().map(|u| u.uid),
            wazuh_dashboard_group.as_ref().map(|g| g.gid),
        )?;
    }

    std::fs::copy(
        "/etc/wazuh-dashboard/opensearch_dashboards.yml",
        "/etc/wazuh-dashboard/opensearch_dashboards.yml.bak",
    )?;

    let public_ip = get_public_ip(bb)?;

    let dashboard_config =
        std::fs::read_to_string("/etc/wazuh-dashboard/opensearch_dashboards.yml")
            .context("Could not read opensearch dsahboards configuration")?;

    let mut dashboard_config = serde_yaml_ng::from_str::<Value>(&dashboard_config)
        .context("Could not parse opensearch dsahboards configuration")?;

    if let Value::Mapping(top) = &mut dashboard_config {
        top.insert("server.host".into(), "0.0.0.0".into());
        top.insert(
            "opensearch.hosts".into(),
            format!("https://{public_ip}:9200").into(),
        );
    }

    std::fs::write(
        "/etc/wazuh-dashboard/opensearch_dsahboards.yml",
        serde_yaml_ng::to_string(&dashboard_config)
            .context("Could not serialize opensearch dsahboards configuration")?,
    )
    .context("Could not save opensearch dsahboards configuration")?;

    system("systemctl daemon-reload")?;
    system("systemctl enable wazuh-dashboard")?;
    system("systemctl start wazuh-dashboard")?;

    let mut dashboard_config_2 = None;

    for i in 0..15 {
        match std::fs::read_to_string("/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml") {
            Ok(v) => {
                let Ok(_) = serde_yaml_ng::from_str::<Value>(&v) else {
                    continue;
                };
                dashboard_config_2 = Some(v);
                break;
            }
            Err(e) => {
                eprintln!(
                    "Attempt {}; Error waiting for wazuh dashboard to generate configuration file: {e}",
                    i + 1
                );
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        };
    }

    let mut dashboard_config_2 = serde_yaml_ng::from_str::<Value>(
        &dashboard_config_2.ok_or(eyre::eyre!("Could not get wazuh dashboard configuration"))?,
    )?;

    if let Value::Mapping(top) = &mut dashboard_config_2
        && let Some(Value::Sequence(hosts)) = top.get_mut("hosts")
        && let Some(Value::Mapping(default)) =
            hosts.iter_mut().find(|host| host.get("default").is_some())
    {
        default.insert("url".into(), format!("https://{public_ip}").into());
    }

    println!(
        "{}",
        "--- Successfully installed and configured wazuh dashboards!".green()
    );

    println!("--- Enabling dark mode in wazuh dashboards...");

    {
        use reqwest::blocking::Client;

        let root_cert = reqwest::Certificate::from_pem(
            std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?.as_bytes(),
        )?;

        let client = Client::builder().add_root_certificate(root_cert).build()?;

        let response = client
            .get(format!("https://{public_ip}:443/api/status"))
            .basic_auth("admin", Some("admin"))
            .send()
            .map_err(eyre::Report::from)
            .and_then(|r| r.json::<serde_json::Value>().map_err(eyre::Report::from));

        match response {
            Ok(v) => {
                println!("{v}");
                println!("--- Enabled dark mode in wazuh dashboards");
            }
            Err(e) => {
                eprintln!("Could not set dark mode in Wazuh dashboards!");
            }
        }
    }

    Ok(())
}

fn rotate_credentials(bb: &Busybox, new_pass: &str) -> eyre::Result<()> {
    println!("--- Rotating server credentials");

    system(
        "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --api --change-all --admin-user wazuh --admin-password wazuh",
    )?;

    system(&format!(
        r#"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p "{new_pass}""#
    ))?;

    system("systemctl restart wazuh-indexer")?;
    system("systemctl restart wazuh-manager")?;
    system("systemctl restart filebeat")?;
    system("systemctl restart wazuh-dashboard")?;

    println!("{}", "--- Successfully reset credentials!".green());

    let public_ip = get_public_ip(bb)?;

    {
        use reqwest::blocking::Client;

        let root_cert = reqwest::Certificate::from_pem(
            std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?.as_bytes(),
        )?;

        let client = Client::builder().add_root_certificate(root_cert).build()?;

        let mut i = 0;
        loop {
            i += 1;
            if i % 10 == 0 {
                println!("Waiting for Dashboards {i}...");
            }
            std::thread::sleep(std::time::Duration::from_secs(1));

            let Ok(res) = client
                .get(format!("https://{public_ip}:443/api/status"))
                .basic_auth("admin", Some(&new_pass))
                .send()
            else {
                continue;
            };
            let Ok(json) = res.json::<serde_json::Value>() else {
                continue;
            };

            if json["status"]["overall"]["state"].as_str() == Some("green") {
                break;
            }
        }
    }

    println!("Waiting for services to be back up...");

    Ok(())
}

fn translate_pipeline_elk_to_wazuh(
    pipeline: &mut serde_json::Map<String, serde_json::Value>,
) -> eyre::Result<()> {
    pipeline.remove("created_date_millis");
    pipeline.remove("modified_date_millis");

    let Some(serde_json::Value::Array(processors)) = pipeline.remove("processors") else {
        eyre::bail!("Could not find processors");
    };

    fn handle_processor(processor: serde_json::Value) -> Option<serde_json::Value> {
        use serde_json::Value as V;

        let V::Object(mut processor) = processor else {
            return Some(processor);
        };

        if let Some(V::Object(community_id)) = processor.get_mut("community_id") {
            if let Some(source) = community_id.remove("source_ip") {
                community_id.insert("source_ip_field".into(), source);
            } else {
                community_id.insert("source_ip_field".into(), "source.ip".into());
            }

            if let Some(source) = community_id.remove("source_port") {
                community_id.insert("source_port_field".into(), source);
            } else {
                community_id.insert("source_port_field".into(), "source.port".into());
            }

            if let Some(destination) = community_id.remove("destination_ip") {
                community_id.insert("destination_ip_field".into(), destination);
            } else {
                community_id.insert("destination_ip_field".into(), "destination.ip".into());
            }

            if let Some(destination) = community_id.remove("destination_port") {
                community_id.insert("destination_port_field".into(), destination);
            } else {
                community_id.insert("destination_port_field".into(), "destination.port".into());
            }

            community_id.remove("icmp_type");
            community_id.remove("icmp_code");
        }

        if let Some(V::Object(m)) = processor.get("uri_parts") {
            let field = m.get("field").and_then(V::as_str)?;

            return Some(serde_json::json!({
                "copy": {
                    "source_field": field,
                    "target_field": "url.original",
                    "ignore_missing": true
                }
            }));
        }

        if let Some(V::Object(m)) = processor.get("registered_domain") {
            let field = m.get("field")?;
            let target_field = m.get("target_field")?;

            return Some(serde_json::json!({
                "copy": {
                    "source_field": field,
                    "target_field": target_field,
                    "ignore_missing": true
                }
            }));
        }

        if let Some(V::Object(set)) = processor.get("set")
            && let Some(V::String(copy_from)) = set.get("copy_from")
            && let Some(V::String(field)) = set.get("field")
        {
            let ignore_failure = set
                .get("ignore_failure")
                .and_then(V::as_bool)
                .unwrap_or_default();

            return Some(serde_json::json!({
                "copy": {
                    "source_field": copy_from,
                    "target_field": field,
                    "ignore_missing": ignore_failure
                }
            }));
        }

        for (_, proc_obj) in processor.iter_mut() {
            if let V::Object(p) = proc_obj
                && let Some(V::Array(on_failure)) = p.remove("on_failure")
            {
                p.insert(
                    "on_failure".into(),
                    on_failure
                        .into_iter()
                        .filter_map(handle_processor)
                        .collect::<V>(),
                );
            }
        }

        Some(V::Object(processor))
    }

    let processors = processors
        .into_iter()
        .filter_map(handle_processor)
        .collect::<serde_json::Value>();

    pipeline.insert("processors".into(), processors);

    Ok(())
}

fn import_pipelines(
    bb: &Busybox,
    args: &WazuhSubcommandArgs,
    wazuh_password: &str,
    elk_password: &str,
) -> eyre::Result<()> {
    println!("--- Checking for jiujitsu ELK...");

    if !std::fs::exists(&args.jj_elastic_location)? {
        println!("--- jiujitsu ELK not detected! Skipping import pipelines step...");
        return Ok(());
    }

    println!(
        "{}",
        "--- Proceeding to import jiujitsu ELK pipelines...".green()
    );

    let cert = std::fs::read_to_string(
        args.jj_elastic_location
            .join("elasticsearch")
            .join("config")
            .join("certs")
            .join("http_ca.crt"),
    )?;
    let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;

    let pipelines = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()?
        .get("https://localhost:10200/_ingest/pipeline")
        .basic_auth("elastic", Some(elk_password))
        .header("kbn-xsrf", "true")
        .send()?
        .json::<serde_json::Value>()?;

    let serde_json::Value::Object(mut pipelines) = pipelines else {
        eyre::bail!("Could not download current pipelines");
    };

    let cert = std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?;
    let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;
    let wazuh_client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()?;

    let public_ip = get_public_ip(bb)?;

    for beat in ["auditbeat", "filebeat", "winlogbeat", "packetbeat"] {
        let create_index_result = wazuh_client
            .put(format!(
                "https://{public_ip}:9200/{beat}-{}",
                args.jj_elastic_version
            ))
            .basic_auth("admin", Some(wazuh_password))
            .send()
            .context(format!("Could not create index for storing {beat} data"))?
            .json::<serde_json::Value>()?;

        println!("{create_index_result}");
    }

    let settings_update_result = wazuh_client
        .put(format!("https://{public_ip}:9200/_cluster/settings"))
        .basic_auth("admin", Some(wazuh_password))
        .header("content-type", "application/json")
        .body(r#"{
    "persistent": {
        "script.max_compilations_rate": "10000/1m"
    }
}"#)
        .send()
        .context("Could not update pipeline compilation limit (this will limit the effectiveness of Packetbeat TLS data)")?
        .json::<serde_json::Value>()?;

    println!("{settings_update_result}");

    for (name, value) in pipelines.iter_mut() {
        if !(name.starts_with("auditbeat")
            || name.starts_with("filebeat")
            || name.starts_with("packetbeat")
            || name.starts_with("winlogbeat")
            || name.starts_with("metricbeat"))
        {
            continue;
        }

        print!("Transferring pipeline {name}...");

        let serde_json::Value::Object(pipeline) = value else {
            continue;
        };

        if translate_pipeline_elk_to_wazuh(pipeline).is_err() {
            continue;
        }

        let Ok(pipeline_json) = serde_json::to_string(&pipeline) else {
            continue;
        };

        match wazuh_client
            .put(format!("https://{public_ip}:9200/_ingest/pipeline/{name}"))
            .basic_auth("admin", Some(wazuh_password))
            .header("content-type", "application/json")
            .body(pipeline_json)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(v) => {
                if let serde_json::Value::Object(ref o) = v
                    && o.get("acknowledged") == Some(&(true.into()))
                {
                    println!(" {}", "Success".green());
                } else {
                    println!("\n  Failed to import pipeline {name}: {v}")
                }
            }
            Err(e) => {
                println!("\n  Failed to contact Wazuh server to import pipeline {name}: {e}");
            }
        }
    }

    println!("{}", "--- Successfully imported pipelines!".green());

    Ok(())
}

fn import_direct_from_beats(
    bb: &Busybox,
    args: &WazuhSubcommandArgs,
    wazuh_password: &str,
) -> eyre::Result<()> {
    use reqwest::blocking::multipart::{Form, Part};

    println!("--- Importing beats configuration directly");

    let cert = std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?;
    let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;

    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()?;

    let public_ip = get_public_ip(bb)?;

    let settings_update_result = client
        .put(format!("https://{public_ip}:9200/_cluster/settings"))
        .basic_auth("admin", Some(wazuh_password))
        .header("content-type", "application/json")
        .body(r#"{
    "persistent": {
        "script.max_compilations_rate": "10000/1m"
    }
}"#)
        .send()
        .context("Could not update pipeline compilation limit (this will limit the effectiveness of Packetbeat TLS data)")?
        .json::<serde_json::Value>()?;

    println!("{settings_update_result}");

    for beat in [
        "auditbeat",
        "packetbeat",
        "filebeat",
        "metricbeat",
        "winlogbeat",
    ] {
        println!("  --- Importing {beat} configuration...");

        let (ingest_pipelines, fields) = if beat == "winlogbeat" {
            let zip = std::io::BufReader::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(args.jj_elastic_share_location.join("winlogbeat.zip"))?,
            );
            let mut zip = zip::read::ZipArchive::new(zip)?;

            let fields = {
                let mut fields = zip.by_name(&format!(
                    "winlogbeat-{}-windows-x86_64/fields.yml",
                    args.jj_elastic_version
                ))?;
                let mut fields_string = String::new();
                fields.read_to_string(&mut fields_string)?;
                fields_string
            };

            let mut ingest_pipelines = vec![];

            for i in 0..zip.len() {
                let mut file = match zip.by_index(i) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("  Could not search for winlogbeat ingest pipeline: {e}");
                        continue;
                    }
                };

                if file.is_dir() {
                    continue;
                }

                let file_name = file.name().to_owned();

                if !file_name.ends_with(".yml") || !file_name.contains("ingest") {
                    continue;
                }

                let Some(pipeline_name) = file_name.strip_suffix(".yml") else {
                    continue;
                };
                let Some(sep_idx) = pipeline_name.rfind("/") else {
                    continue;
                };

                let mut ingest_string = String::new();
                file.read_to_string(&mut ingest_string)?;

                ingest_pipelines.push((pipeline_name[sep_idx + 1..].to_string(), ingest_string));
            }

            (ingest_pipelines, fields)
        } else {
            let gzip = std::io::BufReader::new(
                std::fs::OpenOptions::new().read(true).open(
                    args.jj_elastic_share_location
                        .join(format!("{beat}.tar.gz")),
                )?,
            );
            let mut archive = tar::Archive::new(flate2::bufread::GzDecoder::new(gzip));

            let mut ingest_pipelines = vec![];

            let mut fields = None;

            for entry in archive.entries()? {
                let mut entry = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("  Could not search for {beat} ingest pipeline: {e}");
                        continue;
                    }
                };

                let Some(path) = entry
                    .path()
                    .ok()
                    .and_then(|p| p.to_str().map(str::to_owned))
                else {
                    continue;
                };

                if path == format!("{beat}-{}-linux-x86_64/fields.yml", args.jj_elastic_version) {
                    let mut fields_string = String::new();
                    entry
                        .read_to_string(&mut fields_string)
                        .context("Could not read fields.yml from beat")?;
                    fields = Some(fields_string);
                } else if path.contains("ingest") && path.ends_with(".yml") {
                    let mut pipeline_string = String::new();
                    if let Err(e) = entry.read_to_string(&mut pipeline_string) {
                        eprintln!("  Error reading ingest pipeline from archive: {e}");
                    } else {
                        let Some(pipeline_name) = path.strip_suffix(".yml") else {
                            continue;
                        };
                        let mut parts = pipeline_name.rsplit('/');

                        let Some(pipeline_name) = parts.next() else {
                            continue;
                        };
                        let Some(_ingest) = parts.next() else {
                            continue;
                        };
                        let Some(module2) = parts.next() else {
                            continue;
                        };
                        let Some(module1) = parts.next() else {
                            continue;
                        };

                        ingest_pipelines.push((
                            format!("{module1}-{module2}-{pipeline_name}"),
                            pipeline_string,
                        ));
                    }
                }
            }

            (
                ingest_pipelines,
                fields.ok_or(eyre::eyre!("Did not find fields.yml for {beat}!"))?,
            )
        };

        let fields = serde_yaml_ng::from_str::<serde_json::Value>(&fields)
            .context(format!("Could not parse fields.yml for {beat}"))?;

        let mut index_template = super::elk::convert_fields_to_index_template(
            &beat,
            fields.clone(),
            &args.jj_elastic_version,
            |p, m| {
                if p.is_empty() {
                    return false;
                }

                let serde_json::Value::Object(m) = m else {
                    return false;
                };

                if m.get("deprecated").is_some() {
                    return false;
                }

                m.remove("unit");
                m.remove("metric_type");
                m.remove("definition");
                m.remove("release");
                m.remove("dimension");

                // an ode to mispellings in official data
                m.remove("formate");
                m.remove("descriprtion");
                m.remove("decsription");

                if m.get("type").and_then(serde_json::Value::as_str) == Some("flattened") {
                    m.insert("type".into(), "object".into());
                }
                if m.get("type").and_then(serde_json::Value::as_str) == Some("constant_keyword") {
                    m.insert("type".into(), "keyword".into());
                }

                if m.get("type").and_then(serde_json::Value::as_str) == Some("scaled_float")
                    && m.get("scaling_factor").is_none()
                {
                    m.insert("scaling_factor".into(), 1000.into());
                }

                if m.get("type").and_then(serde_json::Value::as_str) == Some("array") {
                    return false;
                }

                if !matches!(
                    m.get("type").and_then(serde_json::Value::as_str),
                    Some("keyword" | "text")
                ) {
                    m.remove("ignore_above");
                }

                if m.get("type").and_then(serde_json::Value::as_str) == Some("wildcard")
                    && let Some(fields) = m.get("fields").and_then(serde_json::Value::as_object)
                    && let Some((entry, value)) = (&fields).into_iter().next()
                    && entry == "text"
                    && value.get("type").and_then(serde_json::Value::as_str)
                        == Some("match_only_text")
                {
                    m.insert("type".into(), "keyword".into());
                }
                m.remove("fields");

                true
            },
        )?;

        if let Some(serde_json::Value::Object(m)) = index_template
            .get_mut("template")
            .and_then(|t| t.get_mut("settings"))
            .and_then(|s| s.get_mut("index"))
        {
            m.remove("lifecycle");
            m.insert("max_docvalue_fields_search".into(), 1000.into());
        }

        let index_template_body = serde_json::to_string(&index_template)?;

        let response = client
            .post(format!(
                "https://{public_ip}:9200/_index_template/{beat}-{}",
                args.jj_elastic_version
            ))
            .basic_auth("admin", Some(&wazuh_password))
            .header("content-type", "application/json")
            .body(index_template_body.clone())
            .send()
            .context("Could not contact opensearch server")?
            .json::<serde_json::Value>()
            .context("Could not parse response from opensearch")?;

        if let Some(e) = response.get("error") {
            eprintln!("  Could not import index template for {beat}: {e}");
            continue;
        }

        println!("  Successfully imported {beat} index template! Creating data stream...");

        let response = client
            .put(format!(
                "https://{public_ip}:9200/_data_stream/{beat}-{}",
                args.jj_elastic_version
            ))
            .basic_auth("admin", Some(&wazuh_password))
            .send()
            .context("Could not contact Wazuh opensearch server")?
            .json::<serde_json::Value>()
            .context("Could not parse response from opensearch")?;

        if response.get("acknowledged") == Some(&(true.into())) {
            println!("  Successfully uploaded data stream! Importing ingest pipelines...");
        } else if &response["error"]["type"]
            != &serde_json::Value::String("resource_already_exists_exception".to_string())
        {
            eprintln!("  Issues uploading data stream: {response}");
            continue;
        } else {
            eprintln!("  Data stream already exists; moving on...");
        }

        for (name, ingest_pipeline) in ingest_pipelines {
            print!("    Importing pipeline {name}...");

            let ingest_pipeline =
                match serde_yaml_ng::from_str::<serde_json::Value>(&ingest_pipeline) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Could not process ingest pipeline for {beat}: {e}");
                        continue;
                    }
                };

            let module_name = {
                let mut name_parts = name.rsplit('-');
                name_parts.next();
                let mut module_name = name_parts.collect::<Vec<_>>();
                module_name.reverse();
                module_name.join("-")
            };

            let serde_json::Value::Object(mut ingest_pipeline) = ingest_pipeline else {
                continue;
            };

            if let Some(serde_json::Value::Array(processors)) =
                ingest_pipeline.get_mut("processors")
            {
                for processor in processors {
                    if let Some(pipeline) = processor.get_mut("pipeline")
                        && let Some(name) = pipeline.get_mut("name")
                        && let serde_json::Value::String(name) = name
                        && let Some(inner_name) = name
                            .strip_suffix("\" >}")
                            .and_then(|s| s.strip_prefix("{< IngestPipeline \""))
                    {
                        if module_name.is_empty() {
                            *name = format!("{beat}-{}-{inner_name}", args.jj_elastic_version);
                        } else {
                            *name = format!(
                                "{beat}-{}-{module_name}-{inner_name}",
                                args.jj_elastic_version
                            );
                        }
                    }
                }
            }

            if translate_pipeline_elk_to_wazuh(&mut ingest_pipeline).is_err() {
                continue;
            }

            let Ok(pipeline_json) = serde_json::to_string(&ingest_pipeline) else {
                continue;
            };

            let name = format!("{beat}-{}-{name}", args.jj_elastic_version);

            match client
                .put(format!("https://{public_ip}:9200/_ingest/pipeline/{name}"))
                .basic_auth("admin", Some(&wazuh_password))
                .header("content-type", "application/json")
                .body(pipeline_json)
                .send()
                .and_then(|r| r.json::<serde_json::Value>())
            {
                Ok(v) => {
                    if let serde_json::Value::Object(ref o) = v
                        && o.get("acknowledged") == Some(&(true.into()))
                    {
                        println!(" {}", "Success".green());
                    } else {
                        println!("\n      Failed to import pipeline {name}: {v}")
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\n      Failed to contact wazuh server to import pipeline {name}: {e}"
                    );
                }
            }
        }

        println!("  Attempted imports of ingest pipelines; uploading data view...");

        let data_view = super::elk::convert_fields_to_data_view(
            &beat,
            fields.clone(),
            &args.jj_elastic_version,
            |p, m| {
                use serde_json::Value as V;

                let V::Object(m) = m else {
                    return false;
                };

                if p == "url.original" {
                    m.insert("type".into(), "string".into());
                    m.insert("aggregatable".into(), true.into());

                    return true;
                } else if p.starts_with("url.original") {
                    return false;
                }

                true
            },
        )?;
        let data_view_body = serde_json::to_string(&data_view)?;

        let part = Part::bytes(data_view_body.as_bytes().to_owned()).file_name("input.ndjson");
        let form = Form::new().part("file", part);

        let response = client
            .post(format!(
                "https://{public_ip}/api/saved_objects/_import?overwrite=true"
            ))
            .basic_auth("admin", Some(&wazuh_password))
            .header("osd-xsrf", "true")
            .multipart(form)
            .send()
            .context("Could not contact Wazuh dashboard")?
            .json::<serde_json::Value>()
            .context("Could not parse response from Wazuh dashboard")?;

        println!("{response}");

        println!("  Successfully uploaded {beat} data view!");
        println!("{}", format!("  --- {beat} successfully set up!").green());
    }

    println!(
        "{}",
        "--- Successfully imported beats configuration!".green()
    );

    Ok(())
}

fn forward_jj_logstash(
    bb: &Busybox,
    args: &WazuhSubcommandArgs,
    wazuh_password: &str,
) -> eyre::Result<()> {
    println!("--- Checking for jiujitsu ELK...");

    if !std::fs::exists(&args.jj_elastic_location)? {
        println!("--- jiujitsu ELK not detected! Skipping import pipelines step...");
        return Ok(());
    }

    println!(
        "{}",
        "--- Proceeding to configure jiujitsu Logstash to forward data to Wazuh Opensearch..."
            .green()
    );

    let install_logstash_opensearch = || -> eyre::Result<()> {
        system(&format!(
            "{}/logstash/bin/logstash-plugin install logstash-output-opensearch",
            args.jj_elastic_location.display()
        ))?;

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(install_logstash_opensearch)??;
    } else {
        install_logstash_opensearch()?;
    }

    println!("--- Successfully installed opensearch output plugin for logstash!");

    std::fs::copy(
        "/etc/wazuh-indexer/certs/root-ca.pem",
        &format!(
            "{}/wazuh_http_ca.crt",
            args.jj_elastic_share_location.display()
        ),
    )?;

    let mut previous_pipeline_config = serde_yaml_ng::from_slice::<serde_json::Value>(
        &std::fs::read(
            args.jj_elastic_location
                .join("logstash")
                .join("config")
                .join("pipelines.yml"),
        )
        .context("Could not read previous logstash pipeline configuration")?,
    )
    .context("Could not parse previous logstash pipeline configuration")?;

    if let serde_json::Value::Array(a) = &mut previous_pipeline_config
        && !a.iter().any(|p| p["pipeline.id"].as_str() == Some("wazuh"))
    {
        a.push(serde_json::json!({
            "pipeline.id": "wazuh",
            "path.config": format!("{}/logstash/config/wazuh.conf.d/*.conf", args.jj_elastic_location.display()),
            "pipeline.ecs_compatibility": "disabled"
        }));

        std::fs::write(
            args.jj_elastic_location
                .join("logstash")
                .join("config")
                .join("pipelines.yml"),
            serde_yaml_ng::to_string(&previous_pipeline_config)?,
        )?;
    }

    std::fs::set_permissions(
        &format!(
            "{}/wazuh_http_ca.crt",
            args.jj_elastic_share_location.display()
        ),
        PermissionsExt::from_mode(0o644),
    )?;

    std::fs::create_dir_all(&format!(
        "{}/logstash/config/wazuh.conf.d",
        args.jj_elastic_location.display()
    ))?;

    std::fs::write(
        &format!(
            "{}/logstash/config/wazuh.conf.d/pipeline.conf",
            args.jj_elastic_location.display()
        ),
        LOGSTASH_WAZUH_CONF
            .replace(
                "$ES_SHARE",
                &format!("{}", args.jj_elastic_share_location.display()),
            )
            .replace("$WAZUH_PASSWORD", wazuh_password)
            .replace("$WAZUH_IP", &get_public_ip(bb)?),
    )?;

    std::fs::write(
        &format!(
            "{}/logstash/config/conf.d/pipeline-wazuh.conf",
            args.jj_elastic_location.display()
        ),
        "output { pipeline { send_to => [wazuh] } }",
    )?;

    system("systemctl restart jj-logstash")?;

    println!(
        "{}",
        "--- Successfully configured logstash to duplicate records to Wazuh!".green()
    );

    Ok(())
}

fn install_jj_logstash(bb: &Busybox, args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    println!("--- Installing and configuring logstash...");

    let public_ip = get_public_ip(bb)?;

    super::elk::untar_package(
        args.jj_elastic_share_location.join("logstash.tar.gz"),
        format!("logstash-{}", args.jj_elastic_version),
        args.jj_elastic_location.join("logstash"),
    )?;

    println!("Extracted package");

    let ls_home = args.jj_elastic_location.join("logstash");
    let ls_path_conf = ls_home.join("config");

    std::fs::write(
        "/usr/lib/systemd/system/jj-logstash.service",
        super::elk::LOGSTASH_SERVICE
            .replace("$LS_HOME", &format!("{}", ls_home.display()))
            .replace("$LS_PATH_CONF", &format!("{}", ls_path_conf.display())),
    )
    .context("Could not write systemd service for logstash")?;

    println!("Creating user and group...");

    bb.command("addgroup")
        .args(["-S", "jj-logstash"])
        .output()?;

    bb.command("adduser")
        .args([
            "-h",
            "/nonexistent",
            "-G",
            "jj-logstash",
            "-S",
            "-H",
            "-D",
            "jj-logstash",
        ])
        .output()?;

    super::elk::apply_selinux_labels_to_elastic_package(
        &ls_home,
        &ls_path_conf,
        &ls_home.join("bin"),
        &ls_home.join("data"),
    )?;

    println!("Configuring TLS for Logstash...");
    let (ca_crt, ls_crt, ls_privkey) = {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        };

        let ca_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ls_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let ips = Some(public_ip.to_string())
            .into_iter()
            .chain(args.public_nat_ip.as_ref().map(Ipv4Addr::to_string))
            .collect::<Vec<_>>();

        let mut ca_params = CertificateParams::new(ips.clone())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let ca_crt = ca_params.self_signed(&ca_pair)?;

        let ls_params = CertificateParams::new(ips)?;
        let ls_cert = ls_params.signed_by(&ls_pair, &Issuer::new(ca_params, ca_pair))?;

        (ca_crt.pem(), ls_cert.pem(), ls_pair.serialize_pem())
    };

    std::fs::write(args.jj_elastic_share_location.join("http_ca.crt"), ca_crt)?;
    std::fs::write(ls_path_conf.join("logstash.crt"), ls_crt)?;
    std::fs::write(ls_path_conf.join("logstash.key"), ls_privkey)?;

    let logstash_user = passwd::load_users("jj-logstash")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.uid)
        .map(|v| v.into());
    let logstash_group = passwd::load_groups("jj-logstash")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.gid)
        .map(|v| v.into());

    let dir_perms: Permissions = PermissionsExt::from_mode(0o700);
    let file_perms: Permissions = PermissionsExt::from_mode(0o700);

    for entry in walkdir::WalkDir::new(&ls_home) {
        let Ok(entry) = entry else {
            continue;
        };

        if entry.file_type().is_dir() {
            let _ = std::fs::set_permissions(entry.path(), dir_perms.clone());
            let _ = chown(entry.path(), logstash_user, logstash_group);
        } else {
            let _ = std::fs::set_permissions(entry.path(), file_perms.clone());
            let _ = chown(entry.path(), logstash_user, logstash_group);
        }
    }

    std::fs::create_dir_all(ls_path_conf.join("conf.d"))?;
    std::fs::write(
        ls_path_conf.join("logstash.yml"),
        format!(
            "api.enabled: false\npath.data: {}\npath.logs: {}\n",
            ls_home.join("data").display(),
            ls_home.join("logs").display(),
        ),
    )?;
    std::fs::write(
        ls_path_conf.join("pipelines.yml"),
        serde_yaml_ng::to_string(&serde_json::json!([
            {
                "pipeline.id": "main",
                "path.config": format!("{}/*.conf", ls_path_conf.join("conf.d").display()),
                "pipeline.ecs_compatibility": "disabled"
            }
        ]))?,
    )?;
    std::fs::write(
        ls_path_conf.join("conf.d").join("pipeline.conf"),
        format!(
            r#"
input {{
    beats {{
        port => 5044
        ssl_enabled => true
        ssl_certificate => "{0}/logstash.crt"
        ssl_key => "{0}/logstash.key"
    }}
}}
"#,
            ls_path_conf.display()
        ),
    )?;

    system("systemctl daemon-reload")?;
    system("systemctl enable jj-logstash")?;
    system("systemctl restart jj-logstash")?;

    println!("{}", "--- Base logstash configured!".green());

    Ok(())
}

fn install_beats(bb: &Busybox, args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    println!("--- Installing beats...");

    let public_ip = get_public_ip(bb)?;

    let mut threads = Vec::new();

    for pkg in ["filebeat", "auditbeat", "packetbeat"] {
        let src_path = args.jj_elastic_share_location.join(format!("{pkg}.tar.gz"));
        let dest_path = args.jj_elastic_location.join(pkg);

        threads.push(std::thread::spawn(move || -> eyre::Result<()> {
            super::elk::untar_beat(src_path, dest_path)?;
            println!("Unpacked {pkg}!");

            Ok(())
        }));
    }

    for thread in threads {
        match thread.join() {
            Ok(r) => r?,
            Err(_) => {
                eprintln!(
                    "{}",
                    "!!! Could not join extract thread due to panic!".red()
                );
            }
        }
    }

    for pkg in ["filebeat", "auditbeat", "packetbeat"] {
        let dest_path = args.jj_elastic_location.join(pkg);

        super::elk::apply_selinux_labels_to_elastic_package(
            &dest_path,
            &dest_path.join(format!("{pkg}.yml")),
            &dest_path.join(pkg),
            &dest_path.join("data"),
        )?;
    }

    std::fs::write(
        "/usr/lib/systemd/system/jj-auditbeat.service",
        super::elk::AUDITBEAT_SERVICE.replace(
            "$AB_HOME",
            &format!("{}/auditbeat", args.jj_elastic_location.display()),
        ),
    )
    .context("Could not write systemd service for auditbeat")?;

    std::fs::write(
        "/usr/lib/systemd/system/jj-filebeat.service",
        super::elk::FILEBEAT_SERVICE.replace(
            "$FB_HOME",
            &format!("{}/filebeat", args.jj_elastic_location.display()),
        ),
    )
    .context("Could not write systemd service for filebeat")?;

    std::fs::write(
        "/usr/lib/systemd/system/jj-packetbeat.service",
        super::elk::PACKETBEAT_SERVICE.replace(
            "$PB_HOME",
            &format!("{}/packetbeat", args.jj_elastic_location.display()),
        ),
    )
    .context("Could not write systemd service for packetbeat")?;

    println!(
        "{}",
        "--- Done installing beats! Configuring now...".green()
    );

    std::fs::write(
        args.jj_elastic_location
            .join("auditbeat")
            .join("auditbeat.yml"),
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}/http_ca.crt"]
"#,
            super::elk::AUDITBEAT_YML,
            &public_ip,
            args.jj_elastic_share_location.display()
        ),
    )?;

    std::fs::write(
        args.jj_elastic_location
            .join("filebeat")
            .join("filebeat.yml"),
        format!(
            r#"
{}

  - module: netflow
    log:
      enabled: true
      var:
        netflow_host: 0.0.0.0
        netflow_port: 2055
        internal_networks:
          - private

  - module: panw
    panos:
      enabled: true
      var.syslog_host: 0.0.0.0
      var.syslog_port: 9001
      var.log_level: 5

  - module: cisco
    ftd:
      enabled: true
      var.syslog_host: 0.0.0.0
      var.syslog_port: 9002
      var.log_level: 5

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}/http_ca.crt"]
"#,
            super::elk::FILEBEAT_YML,
            &public_ip,
            args.jj_elastic_share_location.display()
        )
        .replace(
            "$FILEBEAT_PATH",
            &format!("{}/filebeat", args.jj_elastic_location.display()),
        ),
    )?;

    std::fs::write(
        args.jj_elastic_location
            .join("packetbeat")
            .join("packetbeat.yml"),
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
  ssl:
    enabled: true
    certificate_authorities: ["{}/http_ca.crt"]
"#,
            super::elk::PACKETBEAT_YML,
            &public_ip,
            args.jj_elastic_share_location.display()
        ),
    )?;

    println!("{}", "--- Done configuring beats!".green());

    if let Err(e) = super::elk::disable_auditd() {
        eprintln!("Could not disable auditd: {e}");
    }

    println!("{}", "--- Verifying output".green());

    for beat in ["auditbeat", "packetbeat", "filebeat"] {
        Command::new(args.jj_elastic_location.join(beat).join(beat))
            .current_dir(args.jj_elastic_location.join(beat))
            .args(["test", "output"])
            .spawn()?
            .wait()?;
        system(&format!("systemctl enable jj-{beat}"))?;
        system(&format!("systemctl restart jj-{beat}"))?;
    }

    println!("--- Beats all set up!");

    if !args.dont_install_suricata {
        super::elk::install_suricata(
            bb,
            &super::elk::SuricataInstallArgs {
                use_download_shell: args.use_download_shell,
                sneaky_ip: args.sneaky_ip,
            },
        )?;
    }

    Ok(())
}

fn load_wazuh_dashboards(bb: &Busybox, wazuh_password: &str) -> eyre::Result<()> {
    use reqwest::blocking::multipart::{Form, Part};

    println!("--- Loading Wazuh dashboards...");

    let public_ip = get_public_ip(bb)?;

    let root_cert = reqwest::Certificate::from_pem(
        std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?.as_bytes(),
    )?;

    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(root_cert)
        .build()?;

    for (i, (name, dash)) in WAZUH_DASHBOARDS.iter().enumerate() {
        print!("Importing object {}, '{name}'...", i + 1);

        let part = Part::bytes(*dash).file_name("input.ndjson");
        let form = Form::new().part("file", part);

        let response = client
            .post(format!(
                "https://{public_ip}/api/saved_objects/_import?overwrite=true"
            ))
            .basic_auth("admin", Some(&wazuh_password))
            .header("osd-xsrf", "true")
            .multipart(form)
            .send()?
            .json::<serde_json::Value>()?;

        if response.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
            println!(" {}", "Success".green());
        } else {
            println!(" Error importing dashboard!");
            println!("{response}");
        }
    }

    println!("{}", "--- Successfully loaded Wazuh dashboards".green());

    Ok(())
}

fn tweak_max_compilations_rate(bb: &Busybox, wazuh_password: &str, rate: u32) -> eyre::Result<()> {
    let cert = std::fs::read_to_string("/etc/wazuh-indexer/certs/root-ca.pem")?;
    let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;
    let wazuh_client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()?;

    let public_ip = get_public_ip(bb)?;

    let response = wazuh_client
        .put(format!("https://{public_ip}:9200/_cluster/settings"))
        .basic_auth("admin", Some(wazuh_password))
        .header("content-type", "application/json")
        .body(format!(r#"{{
    "persistent": {{
        "script.max_compilations_rate": "{rate}/1m"
    }}
}}"#))
        .send()
        .context("Could not update pipeline compilation limit (this will limit the effectiveness of Packetbeat TLS data)")?
        .json::<serde_json::Value>()?;

    println!("{response}");
    Ok(())
}

fn install_agents(bb: &Busybox, distro: &Distro, args: &WazuhAgentCommandArgs) -> eyre::Result<()> {
    println!("--- Downloading Wazuh agent installer...");

    let package = if distro.is_rhel_based() {
        "wazuh-agent.rpm"
    } else {
        "wazuh-agent.deb"
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| {
            download_file(
                &format!(
                    "http://{}:{}/{package}",
                    args.wazuh_ip, args.wazuh_share_port
                ),
                format!("/tmp/{package}"),
            )
        })??;
    } else {
        download_file(
            &format!(
                "http://{}:{}/{package}",
                args.wazuh_ip, args.wazuh_share_port
            ),
            format!("/tmp/{package}"),
        )?;
    }

    let hostname = std::fs::read_to_string("/etc/hostname")?;
    let hostname = hostname.trim();

    if distro.is_rhel_based() {
        Command::new("rpm")
            .args(["-ivh", "/tmp/wazuh-agent.rpm"])
            .env("WAZUH_MANAGER", format!("{}", args.wazuh_ip))
            .env("WAZUH_AGENT_NAME", hostname)
            .spawn()?
            .wait()?;
    } else {
        Command::new("dpkg")
            .args(["-i", "/tmp/wazuh-agent.deb"])
            .env("WAZUH_MANAGER", format!("{}", args.wazuh_ip))
            .env("WAZUH_AGENT_NAME", hostname)
            .spawn()?
            .wait()?;
    }

    println!("Wazuh agent installed! Starting...");

    Command::new("/bin/sh")
        .args(["-c", "systemctl daemon-reload"])
        .spawn()?
        .wait()?;

    Command::new("/bin/sh")
        .args(["-c", "systemctl enable wazuh-agent"])
        .spawn()?
        .wait()?;

    Command::new("/bin/sh")
        .args(["-c", "systemctl start wazuh-agent"])
        .spawn()?
        .wait()?;

    println!("{}", "--- Wazuh agent installed and enabled!".green());

    if !args.dont_install_beats {
        super::elk::install_beats(
            bb,
            &super::elk::ElkBeatsArgs {
                dont_install_suricata: true, // we do that ourselves later, don't do it twice
                elastic_install_directory: args.elastic_install_directory.clone(),
                elk_ip: args.wazuh_ip,
                elk_share_port: args.wazuh_share_port,
                sneaky_ip: args.sneaky_ip,
                use_download_shell: args.use_download_shell,
            },
        )?;
    }

    // check outside of dont_install_beats; what if we want to install the agent and suricata, but not beats?
    if !args.dont_install_suricata {
        super::elk::install_suricata(
            bb,
            &super::elk::SuricataInstallArgs {
                use_download_shell: args.use_download_shell,
                sneaky_ip: args.sneaky_ip,
            },
        )?;
    }

    Ok(())
}

fn cleanup(args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    println!("--- Performing cleanup of Wazuh installation directory");

    std::fs::remove_dir_all(&args.working_dir)?;

    if args.independent_logstash_install {
        let _ = std::fs::remove_file(args.jj_elastic_share_location.join("logstash.tar.gz"));
    }

    println!(
        "{}",
        "--- Successfully cleaned temporary working directory".green()
    );

    Ok(())
}
