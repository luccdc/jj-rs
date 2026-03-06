use std::fs::{File, Permissions};
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    thread,
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::{Context, bail};
use flate2::bufread::GzDecoder;
use nix::unistd::chown;
use tar::Archive;
use walkdir::WalkDir;

use crate::{
    pcre,
    utils::{
        busybox::Busybox,
        download_container::DownloadContainer,
        download_file, get_public_ip,
        os_version::get_distro,
        packages::{DownloadSettings, install_apt_packages, install_dnf_packages},
        passwd, qx, system,
    },
};

// Defines a variable called KIBANA_DASHBOARDS of type &'static [&'static str]
// It includes all the ndjson files for kibana dashboards
include!(concat!(env!("OUT_DIR"), "/kibana_dashboards.rs"));

const FILEBEAT_YML: &str = include_str!("elk/filebeat.linux.yml");
const AUDITBEAT_YML: &str = include_str!("elk/auditbeat.linux.yml");
const PACKETBEAT_YML: &str = include_str!("elk/packetbeat.linux.yml");
const LOGSTASH_CONF: &str = include_str!("elk/pipeline.conf");
const ELASTICSEARCH_SERVICE: &str = include_str!("elk/elasticsearch.service");
const KIBANA_SERVICE: &str = include_str!("elk/kibana.service");
const LOGSTASH_SERVICE: &str = include_str!("elk/logstash.service");
const AUDITBEAT_SERVICE: &str = include_str!("elk/auditbeat.service");
const FILEBEAT_SERVICE: &str = include_str!("elk/filebeat.service");
const PACKETBEAT_SERVICE: &str = include_str!("elk/packetbeat.service");
const SURICATA_YAML: &str = include_str!("elk/suricata.yaml");

macro_rules! cpaths {
    ($base:expr, $($others:expr),*$(,)?) => {{
        let mut path: PathBuf = (&$base).into();
        $(
            path.push(&$others);
        )*
        path
    }}
}

#[derive(Parser, Clone, Debug)]
#[command(about)]
pub struct ElkSubcommandArgs {
    /// Version to use for Elasticsearch, Logstash, Kibana, Auditbeat, Filebeat, and Packetbeat
    #[arg(long, short = 'V', default_value = "9.3.0")]
    elastic_version: String,

    /// URL to download Elasticsearch, Logstash, and Kibana from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads")]
    download_url: String,

    /// URL to download Auditbeat, Filebeat, and Packetbeat from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads/beats")]
    beats_download_url: String,

    /// Where to put files to be shared on the network
    #[arg(long, short = 'S', default_value = "/opt/es-share")]
    elasticsearch_share_directory: PathBuf,

    /// Where to install and configure everything ELK related, including beats
    #[arg(long, short = 'e', default_value = "/opt/jj-es")]
    elastic_install_directory: PathBuf,

    /// Disable syslog input
    #[arg(long, short = 'D')]
    disable_syslog: bool,

    /// Syslog input port for Filebeat
    #[arg(long, short = 'l', default_value = "1514")]
    syslog_port: u16,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,
}

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
pub struct ElkBeatsArgs {
    /// The IP address of the ELK server to download resources from and send logs to
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    elk_ip: Ipv4Addr,

    /// The port of the share on the ELK server
    #[arg(long, short = 'p', default_value_t = 8080)]
    elk_share_port: u16,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,

    /// Where to install and configure all the beats
    #[arg(long, short = 'e', default_value = "/opt/jj-es")]
    elastic_install_directory: PathBuf,

    /// Don't install Suricata alongside beats
    #[arg(long, short = 'S')]
    dont_install_suricata: bool,
}

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
pub struct SuricataInstallArgs {
    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,
}

#[derive(Subcommand, Debug)]
pub enum ElkCommands {
    #[command(visible_alias = "in")]
    Install(ElkSubcommandArgs),

    /// Setup ZRAM to provide 4G of swap based on compressed RAM
    #[command(visible_alias = "zr")]
    SetupZram(ElkSubcommandArgs),

    /// Download packages to install ELK for the current distribution and beats for both Debian and RHEL based distributions
    #[command(visible_alias = "dpkg")]
    DownloadPackages(ElkSubcommandArgs),

    /// Extract ELK and beats to later install
    #[command(visible_alias = "epkg")]
    ExtractPackages(ElkSubcommandArgs),

    /// Start and configure elasticsearch
    #[command(visible_alias = "es")]
    SetupElastic(ElkSubcommandArgs),

    /// Configure Kibana to be able to access Elasticsearch and load dashboards
    #[command(visible_alias = "ki")]
    SetupKibana(ElkSubcommandArgs),

    /// Extra step to load Kibana dashboards if such setup fails in the previous step
    #[command(visible_alias = "kd")]
    LoadKibanaDashboards,

    /// Configure Logstash to be able to store to Elasticsearch and configure a pipeline for beats
    #[command(visible_alias = "lo")]
    SetupLogstash(ElkSubcommandArgs),

    /// Configure auditbeat locally and optimize Elasticsearch to handle auditbeat logs
    #[command(visible_alias = "ab")]
    SetupAuditbeat(ElkSubcommandArgs),

    /// Configure packetbeat locally and optimize Elasticsearch to handle packetbeat logs
    #[command(visible_alias = "pb")]
    SetupPacketbeat(ElkSubcommandArgs),

    /// Configure filebeat locally and optimize Elasticsearch to handle filebeat logs. Also configures filebeat to handle ingest for generic rsyslog, netflow, cisco syslog, and palo syslog
    #[command(visible_alias = "fb")]
    SetupFilebeat(ElkSubcommandArgs),

    /// Optimize Elasticsearch to handle winlogbeat logs
    #[command(visible_alias = "wb")]
    SetupWinlogbeat(ElkSubcommandArgs),

    /// Export dashboards to allow for a manual import
    #[command(visible_alias = "exp-db")]
    ExportDashboards,

    /// Install beats and configure the system to send logs to the ELK stack
    #[command(visible_alias = "beats")]
    InstallBeats(ElkBeatsArgs),

    /// Install and configure Suricata, downloading updated rules for it
    #[command(visible_alias = "sur")]
    InstallSuricata(SuricataInstallArgs),
}

/// Install, configure, and manage ELK and beats locally and assist across the network
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Elk {
    #[command(subcommand)]
    command: ElkCommands,
}

impl super::Command for Elk {
    fn execute(self) -> eyre::Result<()> {
        use ElkCommands as EC;

        if let EC::ExportDashboards = self.command {
            let mut out = std::io::stdout().lock();
            for dash in KIBANA_DASHBOARDS {
                out.write_all(dash)?;
            }
            return Ok(());
        }

        if !qx("systemctl --version")?.1.contains("systemd") {
            eprintln!("{}", "!!! ELK utilities require systemd to run".red());
            return Ok(());
        }

        let busybox = Busybox::new()?;

        if let EC::InstallBeats(args) = &self.command {
            return install_beats(&busybox, args);
        }

        let hostname = qx("hostnamectl")?.1;
        if pcre!(&hostname =~ qr/r"Static\+hostname:\s+\(unset\)"/xms) {
            eprintln!("!!! ELK requires a hostname explicitly set to work correctly");
            return Ok(());
        }

        let mut elastic_password = None;

        if let EC::Install(_) = &self.command {
            get_elastic_password(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupZram(_) = &self.command
            && let Err(e) = setup_zram()
        {
            eprintln!("{}{e}", "??? Could not set up zram: ".yellow());
        }

        if let EC::Install(args) | EC::DownloadPackages(args) = &self.command {
            download_packages(args)?;
        }

        if let EC::Install(args) | EC::ExtractPackages(args) = &self.command {
            extract_packages(args)?;
        }

        if let EC::Install(args) | EC::SetupElastic(args) = &self.command {
            setup_elasticsearch(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupKibana(args) = &self.command {
            setup_kibana(&busybox, args)?;
        }

        if let EC::Install(_) | EC::LoadKibanaDashboards = &self.command {
            load_kibana_dashboards(&mut elastic_password)?;
        }

        if let EC::Install(args) | EC::SetupLogstash(args) = &self.command {
            setup_logstash(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupAuditbeat(args) = &self.command {
            setup_auditbeat(&mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupFilebeat(args) = &self.command {
            setup_filebeat(&mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupPacketbeat(args) = &self.command {
            setup_packetbeat(&mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupWinlogbeat(args) = &self.command {
            setup_winlogbeat(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) = &self.command {
            install_suricata(
                &busybox,
                &SuricataInstallArgs {
                    use_download_shell: args.use_download_shell,
                    sneaky_ip: args.sneaky_ip,
                },
            )?;
        } else if let EC::InstallSuricata(args) = &self.command {
            install_suricata(&busybox, args)?;
        }

        if let EC::Install(_) = &self.command {
            println!(
                "
Configuration Notes:
    When Installing and configuring ELK, the following ports should be opened up:
        - 514/udp: Syslog input. Generic from Windows and Linux systems
        - 2055/udp: Netflow input. Useful from network firewalls
        - 5044/tcp: Beats input from endpoints
        - 5601/tcp: Kibana web interface
        - 8080/tcp: Python web server for distributing certificate
        - 9001/udp: Palo Alto Syslog input
        - 9002/udp: Cisco FTD Syslog input
        - 10200/tcp: Elasticsearch
"
            );
        }

        Ok(())
    }
}

fn get_elastic_password(password: &mut Option<String>) -> eyre::Result<String> {
    if let Some(pass) = password.clone() {
        return Ok(pass);
    }

    let mut new_pass = String::new();

    print!("Enter the password for the elastic user: ");
    io::stdout()
        .flush()
        .context("Could not display password prompt")?;
    io::stdin()
        .read_line(&mut new_pass)
        .context("Could not read password from user")?;
    new_pass = new_pass.trim().to_string();

    *password = Some(new_pass.clone());

    Ok(new_pass)
}

fn setup_zram() -> eyre::Result<()> {
    let mods = qx("lsmod")?.1;

    if pcre!(&mods =~ qr/"zram"/xms) {
        println!("{}", "--- Skipping ZRAM setup".green());
        return Ok(());
    }

    if !qx("modprobe zram")?.0.success() {
        bail!("Could not load zram!");
    }

    if !qx("zramctl /dev/zram0 --size=4G")?.0.success() {
        bail!("Could not initialize zram device");
    }

    if !qx("mkswap /dev/zram0")?.0.success() {
        bail!("Could not initialize zram swap space");
    }

    if !qx("swapon --priority=100 /dev/zram0")?.0.success() {
        bail!("Could not enable zram swap space");
    }

    println!("{}", "--- ZRAM has been set up!".green());

    Ok(())
}

fn download_packages(args: &ElkSubcommandArgs) -> eyre::Result<()> {
    let download_packages_internal = |download_shell: bool| -> eyre::Result<()> {
        std::fs::create_dir_all(&args.elasticsearch_share_directory)?;

        let mut download_threads = vec![];

        println!("{}", "--- Downloading elastic packages...".green());

        for pkg in ["elasticsearch", "logstash", "kibana"] {
            let args = args.clone();
            let pkg = pkg.to_string();
            let download_package = move || {
                let mut dest_path = args.elasticsearch_share_directory.clone();
                dest_path.push(format!("{pkg}.tar.gz"));
                let res = download_file(
                    &format!(
                        "{}/{}/{}-{}-linux-x86_64.tar.gz",
                        args.download_url, pkg, pkg, args.elastic_version
                    ),
                    dest_path,
                );
                println!("Done downloading {pkg}!");
                res
            };
            if download_shell {
                download_package()?;
            } else {
                download_threads.push(thread::spawn(download_package));
            }
        }

        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            let download_package = {
                let args = args.clone();
                let beat = beat.to_string();

                move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{beat}.tar.gz"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-linux-x86_64.tar.gz",
                            args.beats_download_url, beat, beat, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {beat} for Linux!");
                    res
                }
            };
            if download_shell {
                download_package()?;
            } else {
                download_threads.push(thread::spawn(download_package));
            }
        }

        for beat in ["winlogbeat", "filebeat", "packetbeat"] {
            let download_package = {
                let args = args.clone();
                let beat = beat.to_string();

                move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{beat}.zip"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-windows-x86_64.zip",
                            args.beats_download_url, beat, beat, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {beat} for Windows!");
                    res
                }
            };
            if download_shell {
                download_package()?;
            } else {
                download_threads.push(thread::spawn(download_package));
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

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| download_packages_internal(true))??;
    } else {
        download_packages_internal(false)?;
    }

    println!(
        "{}",
        "--- Successfully downloaded elastic packages!".green()
    );

    Ok(())
}

fn untar_package(
    src_path: impl AsRef<Path> + AsRef<std::ffi::OsStr> + std::fmt::Debug,
    sub_path: impl AsRef<Path> + AsRef<std::ffi::OsStr> + std::fmt::Debug,
    dest_path: impl AsRef<Path> + AsRef<std::ffi::OsStr> + std::fmt::Debug,
) -> eyre::Result<()> {
    std::fs::create_dir_all(&dest_path)?;
    let backing_file = File::open(src_path).context("Could not open file for decompression")?;
    let buffer = BufReader::new(backing_file);
    let decompress = GzDecoder::new(buffer);
    let mut archive = Archive::new(decompress);

    for entry in archive.entries()? {
        let mut entry = entry?;
        if let Ok(sub_path) = entry.path()?.strip_prefix(&sub_path) {
            if let Some(parent) = sub_path.parent() {
                std::fs::create_dir_all(cpaths!(dest_path, parent))?;
            }
            entry.unpack(cpaths!(dest_path, sub_path))?;
        }
    }

    Ok(())
}

fn extract_packages(args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Extracting elastic packages...".green());

    let mut threads = Vec::new();

    for pkg in ["elasticsearch", "logstash", "kibana"] {
        let src_path = cpaths!(args.elasticsearch_share_directory, format!("{pkg}.tar.gz"));
        let sub_path = format!("{pkg}-{}", args.elastic_version);
        let dest_path = cpaths!(args.elastic_install_directory, pkg);

        threads.push(thread::spawn(move || -> eyre::Result<()> {
            untar_package(src_path, sub_path, dest_path)?;
            println!("Unpacked {pkg}!");
            Ok(())
        }));
    }

    for pkg in ["filebeat", "auditbeat", "packetbeat"] {
        let src_path = cpaths!(args.elasticsearch_share_directory, format!("{pkg}.tar.gz"));
        let sub_path = format!("{pkg}-{}-linux-x86_64", args.elastic_version);
        let dest_path = cpaths!(args.elastic_install_directory, pkg);

        threads.push(thread::spawn(move || -> eyre::Result<()> {
            untar_package(src_path, sub_path, dest_path)?;
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
                    "!!! Could not join download thread due to panic!".red()
                );
            }
        }
    }

    println!("{}", "--- Extracted elastic packages!".green());

    Ok(())
}

fn apply_selinux_labels(home: &Path, path_conf: &Path, path_bin: &Path) -> eyre::Result<()> {
    if qx("getenforce")?.1.contains("Enforcing") {
        println!("SELinux is enabled, configuring contexts...");

        std::fs::create_dir_all(cpaths!(home, "logs"))?;
        std::fs::create_dir_all(cpaths!(home, "data"))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t usr_t {}",
            home.display()
        ))?;
        system(&format!("chcon -u system_u -t usr_t -R {}", home.display()))?;
        system(&format!("restorecon -R {}", home.display()))?;

        let logs = cpaths!(home, "logs");
        system(&format!(
            "semanage fcontext -a -s system_u -t var_log_t {}",
            logs.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t var_log_t -R {}",
            logs.display()
        ))?;
        system(&format!("restorecon -R {}", logs.display()))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t etc_t {}",
            path_conf.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t etc_t -R {}",
            path_conf.display()
        ))?;
        system(&format!("restorecon -R {}", path_conf.display()))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t bin_t {}",
            path_bin.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t bin_t -R {}",
            path_bin.display()
        ))?;
        system(&format!("restorecon -R {}", path_bin.display()))?;

        let data = cpaths!(home, "data");
        system(&format!(
            "semanage fcontext -a -s system_u -t var_lib_t {}",
            data.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t var_lib_t -R {}",
            data.display()
        ))?;
        system(&format!("restorecon -R {}", data.display()))?;
    }

    Ok(())
}

fn setup_elasticsearch(
    bb: &Busybox,
    password: &mut Option<String>,
    args: &ElkSubcommandArgs,
) -> eyre::Result<()> {
    let elastic_password = get_elastic_password(password)?;
    println!("{}", "--- Configuring Elasticsearch".green());

    let es_home = cpaths!(args.elastic_install_directory, "elasticsearch");
    let es_path_conf = cpaths!(es_home, "config");

    std::fs::write(
        "/usr/lib/systemd/system/jj-elasticsearch.service",
        ELASTICSEARCH_SERVICE
            .replace("$ES_HOME", &format!("{}", es_home.display()))
            .replace("$ES_PATH_CONF", &format!("{}", es_path_conf.display())),
    )
    .context("Could not write systemd service for elasticsearch")?;

    println!("Creating jj-elasticsearch group...");
    bb.command("addgroup")
        .args(["-S", "jj-elasticsearch"])
        .output()?;

    println!("Creating user...");
    bb.command("adduser")
        .args([
            "-h",
            "/nonexistent",
            "-G",
            "jj-elasticsearch",
            "-S",
            "-H",
            "-D",
            "jj-elasticsearch",
        ])
        .output()?;

    apply_selinux_labels(&es_home, &es_path_conf, &cpaths!(es_home, "bin"))?;

    let elasticsearch_user = passwd::load_users("jj-elasticsearch")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.uid)
        .map(|v| v.into());
    let elasticsearch_group = passwd::load_groups("jj-elasticsearch")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.gid)
        .map(|v| v.into());

    let dir_perms: Permissions = PermissionsExt::from_mode(0o700);
    let file_perms: Permissions = PermissionsExt::from_mode(0o700);

    println!("Setting permissions...");
    for entry in WalkDir::new(&es_home) {
        let Ok(entry) = entry else {
            continue;
        };

        if entry.file_type().is_dir() {
            let _ = std::fs::set_permissions(entry.path(), dir_perms.clone());
            let _ = chown(entry.path(), elasticsearch_user, elasticsearch_group);
        } else {
            let _ = std::fs::set_permissions(entry.path(), file_perms.clone());
            let _ = chown(entry.path(), elasticsearch_user, elasticsearch_group);
        }
    }

    println!("Performing auto configuration of node...");
    Command::new("/bin/sh")
        .args([
            "-c",
            &format!(
                "sudo -E -u jj-elasticsearch {}/bin/elasticsearch-cli",
                es_home.display()
            ),
        ])
        .current_dir(&es_home)
        .env("ES_HOME", &format!("{}", es_home.display()))
        .env("ES_PATH_CONF", &format!("{}", es_path_conf.display()))
        .env("CLI_NAME", "auto-configure-node")
        .env(
            "CLI_LIBS",
            "modules/x-pack-core,modules/x-pack-security,lib/tools/security-cli",
        )
        .spawn()?
        .wait()?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    println!("Applying jj customizations to elasticsearch...");
    let elasticsearch_config = std::fs::read_to_string(cpaths!(es_path_conf, "elasticsearch.yml"))
        .context("Could not read elasticsearch configuration")?;

    // Why don't we use serde_yaml_ng?
    // Because it parses the entirety of the configuration file as null...

    let port_regex =
        regex::Regex::new("(?ms)(#?http.port: [^\n]+)").expect("Static regex failed after testing");
    let elasticsearch_config = port_regex.replace(&elasticsearch_config, "http.port: 10200");

    let seed_hosts_regex = regex::Regex::new("(?ms)(#?discovery.seed_hosts: [^\n]+)")
        .expect("Static regex failed after testing");
    let elasticsearch_config =
        seed_hosts_regex.replace(&elasticsearch_config, "discovery.seed_hosts: []");

    let discovery_type_regex = regex::Regex::new("(?ms)(#?discovery.type: [^\n]+)")
        .expect("Static regex failed after testing");
    let elasticsearch_config =
        discovery_type_regex.replace(&elasticsearch_config, "discovery.type: single-node");

    let transport_regex = regex::Regex::new("(?ms)(#?transport.port: [^\n]+)")
        .expect("Static regex failed after testing");
    let elasticsearch_config =
        transport_regex.replace(&elasticsearch_config, "transport.port: 10300");

    let elasticsearch_config = elasticsearch_config.replace(
        "cluster.initial_master_nodes",
        "#cluster.initial_master_nodes",
    );

    let elasticsearch_config = if !port_regex.is_match(&elasticsearch_config) {
        elasticsearch_config + "\nhost.port: 10200"
    } else {
        elasticsearch_config
    };
    let elasticsearch_config = if !seed_hosts_regex.is_match(&elasticsearch_config) {
        elasticsearch_config + "\ndiscovery.seed_hosts: []"
    } else {
        elasticsearch_config
    };
    let elasticsearch_config = if !discovery_type_regex.is_match(&elasticsearch_config) {
        elasticsearch_config + "\ndiscovery.type: single-node"
    } else {
        elasticsearch_config
    };
    let elasticsearch_config = if !transport_regex.is_match(&elasticsearch_config) {
        elasticsearch_config + "\ntransport.port: 10300"
    } else {
        elasticsearch_config
    };

    std::fs::write(
        cpaths!(es_path_conf, "elasticsearch.yml"),
        &*elasticsearch_config,
    )
    .context("Could not write elasticsearch configuration")?;

    println!("Starting elasticsearch...");
    system("systemctl enable jj-elasticsearch").context("Could not enable elasticsearch")?;
    system("systemctl start jj-elasticsearch").context("Could not start elasticsearch")?;

    let client = reqwest::blocking::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    #[derive(serde::Deserialize, Debug)]
    struct ElasticStatus {
        status: u16,
    }
    let mut i = 0;
    loop {
        i += 1;
        println!("Waiting for Elasticsearch {i}...");
        std::thread::sleep(std::time::Duration::from_secs(1));

        let Ok(res) = client.get("https://localhost:10200/_cluster/health").send() else {
            continue;
        };
        let Ok(json) = res.json::<ElasticStatus>() else {
            continue;
        };

        // We aren't authenticating yet; we need to run elasticsearch-reset-password
        // But, that requires a working "cluster"...
        if json.status == 401 {
            break;
        }
    }

    println!("Changing password...");

    let mut password_change = Command::new(cpaths!(es_home, "bin", "elasticsearch-reset-password"))
        .current_dir(&es_home)
        .env("ES_HOME", &format!("{}", es_home.display()))
        .env("ES_PATH_CONF", &format!("{}", es_path_conf.display()))
        .args(["-u", "elastic", "-i"])
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()?;

    if let Some(ref mut stdin) = password_change.stdin {
        writeln!(stdin, "y")?;
        writeln!(stdin, "{elastic_password}")?;
        writeln!(stdin, "{elastic_password}")?;
    }

    password_change.wait()?;

    println!("Copying HTTP CA certificate...");

    let perms: Permissions = PermissionsExt::from_mode(0o444);

    let share_dir = cpaths!(args.elasticsearch_share_directory, "http_ca.crt");
    std::fs::copy(cpaths!(es_path_conf, "certs", "http_ca.crt"), &share_dir)?;

    std::fs::set_permissions(share_dir, perms)?;

    println!("{}", "--- Elasticsearch configured!".green());

    Ok(())
}

fn setup_kibana(bb: &Busybox, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Configuring Kibana".green());

    let kbn_home = cpaths!(args.elastic_install_directory, "kibana");
    let kbn_path_conf = cpaths!(kbn_home, "config");
    let es_home = cpaths!(args.elastic_install_directory, "elasticsearch");
    let es_path_conf = cpaths!(es_home, "config");

    std::fs::write(
        "/usr/lib/systemd/system/jj-kibana.service",
        KIBANA_SERVICE
            .replace(
                "$KBN_HOME",
                &format!("{}/kibana", args.elastic_install_directory.display()),
            )
            .replace(
                "$KBN_PATH_CONF",
                &format!("{}/kibana/config", args.elastic_install_directory.display()),
            ),
    )
    .context("Could not write systemd service for kibana")?;

    println!("Creating jj-kibana group...");
    bb.command("addgroup").args(["-S", "jj-kibana"]).output()?;

    println!("Creating user...");
    bb.command("adduser")
        .args([
            "-h",
            "/nonexistent",
            "-G",
            "jj-kibana",
            "-S",
            "-H",
            "-D",
            "jj-kibana",
        ])
        .output()?;

    apply_selinux_labels(&kbn_home, &kbn_path_conf, &cpaths!(kbn_home, "bin"))?;

    let kibana_user = passwd::load_users("jj-kibana")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.uid)
        .map(|v| v.into());
    let kibana_group = passwd::load_groups("jj-kibana")
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|v| v.gid)
        .map(|v| v.into());

    let dir_perms: Permissions = PermissionsExt::from_mode(0o700);
    let file_perms: Permissions = PermissionsExt::from_mode(0o700);

    println!("Setting permissions...");
    for entry in WalkDir::new(&kbn_home) {
        let Ok(entry) = entry else {
            continue;
        };

        if entry.file_type().is_dir() {
            let _ = std::fs::set_permissions(entry.path(), dir_perms.clone());
            let _ = chown(entry.path(), kibana_user, kibana_group);
        } else {
            let _ = std::fs::set_permissions(entry.path(), file_perms.clone());
            let _ = chown(entry.path(), kibana_user, kibana_group);
        }
    }

    println!("Getting enrollment token...");

    let token_output = &Command::new(cpaths!(
        &es_home,
        "bin",
        "elasticsearch-create-enrollment-token"
    ))
    .current_dir(&es_home)
    .env("ES_HOME", format!("{}", es_home.display()))
    .env("ES_PATH_CONF", format!("{}", es_path_conf.display()))
    .args(["-s", "kibana"])
    .output()?;

    std::io::stderr().write_all(&token_output.stderr)?;

    let token = String::from_utf8_lossy(&token_output.stdout)
        .trim()
        .to_owned();

    Command::new("/bin/sh")
        .args([
            "-c",
            &format!(
                "sudo -E -u jj-kibana {} -t {token}",
                cpaths!(kbn_home, "bin", "kibana-setup").display()
            ),
        ])
        .current_dir(&kbn_home)
        .env("KBN_HOME", format!("{}", kbn_home.display()))
        .env("KBN_PATH_CONF", format!("{}", kbn_path_conf.display()))
        .spawn()?
        .wait()?;

    println!("Applying jj customizations to Kibana...");

    let keys = Command::new(cpaths!(kbn_home, "bin", "kibana-encryption-keys"))
        .arg("generate")
        .env("KBN_HOME", format!("{}", kbn_home.display()))
        .env("KBN_PATH_CONF", format!("{}", kbn_path_conf.display()))
        .output()?;

    std::io::stderr().write_all(&keys.stderr)?;

    let keys_regex =
        regex::Regex::new("(?ms)(^xpack\\.[^:]+: [^\n]+)").expect("Statically tested regex failed");
    let keys = String::from_utf8_lossy(&keys.stdout);
    let keys = keys_regex
        .captures_iter(&keys)
        .map(|c| c[1].to_string())
        .collect::<Vec<_>>();

    let kibana_yml = std::fs::read_to_string(cpaths!(kbn_path_conf, "kibana.yml"))?;
    let mut new_kibana_yml =
        pcre!(&kibana_yml =~ s/r"^[^\n]server.host:[^\n]+"/r#"server.host: "0.0.0.0""#/xms);
    new_kibana_yml.push('\n');
    new_kibana_yml.push_str(&keys.join("\n"));
    std::fs::write(cpaths!(kbn_path_conf, "kibana.yml"), new_kibana_yml)?;

    system("systemctl enable jj-kibana")?;
    system("systemctl start jj-kibana")?;

    println!("{}", "--- Waiting for Kibana...".green());

    {
        use reqwest::blocking::Client;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Level {
            level: String,
        }

        #[derive(Deserialize)]
        struct Overall {
            overall: Level,
        }

        #[derive(Deserialize)]
        struct KibanaStatus {
            status: Overall,
        }
        let client = Client::new();

        let mut i = 0;
        loop {
            i += 1;
            println!("Waiting for Kibana {i}...");
            std::thread::sleep(std::time::Duration::from_secs(1));

            let Ok(res) = client.get("http://localhost:5601/api/status").send() else {
                continue;
            };
            let Ok(json) = res.json::<KibanaStatus>() else {
                continue;
            };

            if json.status.overall.level == "available" {
                break;
            }
        }
    }

    println!("{}", "--- Kibana configured!".green());

    Ok(())
}

fn load_kibana_dashboards(password: &mut Option<String>) -> eyre::Result<()> {
    let elastic_password = get_elastic_password(password)?;

    println!("{}", "--- Importing Kibana dashboards...".green());

    use reqwest::blocking::{
        Client,
        multipart::{Form, Part},
    };
    let client = Client::new();

    for (i, dash) in KIBANA_DASHBOARDS.iter().enumerate() {
        println!("Importing dashboard {}...", i + 1);

        let part = Part::bytes(*dash).file_name("input.ndjson");
        let form = Form::new().part("file", part);

        client
            .post("http://localhost:5601/api/saved_objects/_import?overwrite=true")
            .basic_auth("elastic", Some(elastic_password.clone()))
            .header("kbn-xsrf", "true")
            .multipart(form)
            .send()?;
    }

    println!("{}", "--- Kibana dashboards loaded!".green());

    Ok(())
}

fn setup_logstash(
    bb: &Busybox,
    password: &mut Option<String>,
    args: &ElkSubcommandArgs,
) -> eyre::Result<()> {
    println!("{}", "--- Configuring Logstash...".green());

    let ls_home = cpaths!(args.elastic_install_directory, "logstash");
    let ls_path_conf = cpaths!(ls_home, "config");

    std::fs::write(
        "/usr/lib/systemd/system/jj-logstash.service",
        LOGSTASH_SERVICE
            .replace(
                "$LS_HOME",
                &format!("{}/logstash", args.elastic_install_directory.display()),
            )
            .replace(
                "$LS_PATH_CONF",
                &format!(
                    "{}/logstash/config",
                    args.elastic_install_directory.display()
                ),
            ),
    )
    .context("Could not write systemd service for logstash")?;

    println!("Creating jj-logstash group...");
    bb.command("addgroup")
        .args(["-S", "jj-logstash"])
        .output()?;

    println!("Creating user...");
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

    apply_selinux_labels(&ls_home, &ls_path_conf, &cpaths!(ls_home, "bin"))?;

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

    println!("Setting permissions...");
    for entry in WalkDir::new(&ls_home) {
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

    std::fs::create_dir_all("/etc/systemd/system/jj-logstash.service.d")?;

    if std::fs::metadata("/etc/systemd/system/jj-logstash.service.d/api_key.conf").is_err() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct ElasticApiKeys {
            id: String,
            name: String,
            api_key: String,
            encoded: String,
        }

        println!("Requesting new API key for logstash...");
        let es_password = get_elastic_password(password)?;

        let api_key_permissions_body = r#"
{
    "name": "logstash-api-key",
    "role_descriptors": {
        "logstash_writer": {
            "cluster": ["monitor","manage_index_templates","manage_ilm"],
            "index": [{
                "names": ["filebeat-*","winlogbeat-*","auditbeat-*","packetbeat-*","logs-*","jj-*"],
                "privileges": ["view_index_metadata","read","create","manage","manage_ilm"]
            }]
        }
    }
}
"#;

        let cert =
            std::fs::read_to_string(cpaths!(args.elasticsearch_share_directory, "http_ca.crt"))?;
        let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;

        let api_keys = reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .build()?
            .post("https://localhost:10200/_security/api_key")
            .basic_auth("elastic", Some(es_password))
            .header("kbn-xsrf", "true")
            .header("content-type", "application/json")
            .body(api_key_permissions_body)
            .send()?
            .json::<ElasticApiKeys>()?;

        std::fs::write(
            "/etc/systemd/system/jj-logstash.service.d/api_key.conf",
            format!(
                r#"[Service]
Environment="ES_API_KEY={}:{}"
"#,
                api_keys.id, api_keys.api_key
            ),
        )?;
    }

    std::fs::create_dir_all(cpaths!(ls_path_conf, "conf.d"))?;
    std::fs::write(
        cpaths!(ls_path_conf, "logstash.yml"),
        format!(
            "api.enabled: false\npath.data: {}\npath.logs: {}\n",
            cpaths!(ls_home, "data").display(),
            cpaths!(ls_home, "logs").display()
        ),
    )?;
    std::fs::write(
        cpaths!(ls_path_conf, "pipelines.yml"),
        format!(
            "- pipeline.id: main\n  path.config: {}/*.conf\n  pipeline.ecs_compatibility: disabled",
            cpaths!(ls_path_conf, "conf.d").display()
        ),
    )?;
    std::fs::write(
        cpaths!(ls_path_conf, "conf.d", "pipeline.conf"),
        LOGSTASH_CONF
            .replace(
                "$ES_SHARE",
                &format!("{}", args.elasticsearch_share_directory.display()),
            )
            .replace("$ELK_IP", &get_public_ip(&bb)?),
    )?;

    system("systemctl daemon-reload")?;
    system("systemctl enable jj-logstash")?;
    system("systemctl restart jj-logstash")?;

    println!("{}", "--- Logstash configured!".green());

    Ok(())
}

// auditbeat gracefully degrades if it can't hook into the audit socket, but we can
// explicitly disable auditd
fn disable_auditd() -> eyre::Result<()> {
    println!("--- Disabling auditd");

    let auditd_service = crate::utils::systemd::get_service_info("auditd")
        .context("Could not find auditd service")?;

    let Some(path) = auditd_service.get("FragmentPath") else {
        eyre::bail!("Could not find systemd service configuration file for auditd");
    };

    std::fs::write(
        &path,
        std::fs::read_to_string(&path)
            .context("Could not read current auditd systemd configuration")?
            .replace("RefuseManualStop=yes", ""),
    )
    .context("Could not save modified auditd systemd settings")?;

    system("systemctl daemon-reload")?;
    system("systemctl stop auditd")?;
    system("systemctl disable auditd")?;

    Ok(())
}

fn setup_auditbeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up auditbeat".green());

    if let Err(e) = disable_auditd() {
        eprintln!("Could not disable auditd: {e}");
    }

    std::fs::write(
        "/usr/lib/systemd/system/jj-auditbeat.service",
        AUDITBEAT_SERVICE.replace(
            "$AB_HOME",
            &format!("{}/auditbeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for auditbeat")?;

    let es_password = get_elastic_password(password)?;

    let ab_home = cpaths!(args.elastic_install_directory, "auditbeat");

    apply_selinux_labels(
        &ab_home,
        &cpaths!(ab_home, "auditbeat.yml"),
        &cpaths!(ab_home, "auditbeat"),
    )?;

    std::fs::write(
        cpaths!(ab_home, "auditbeat.yml"),
        format!(
            r#"
{AUDITBEAT_YML}

output.elasticsearch:
  hosts: ["https://localhost:10200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "{}/http_ca.crt"
"#,
            args.elasticsearch_share_directory.display()
        ),
    )?;

    system(&format!(
        "{0}/auditbeat --path.home {0} --path.config {0} --path.data {0}/data --path.logs {0}/logs setup",
        ab_home.display()
    ))?;

    std::fs::write(
        cpaths!(ab_home, "auditbeat.yml"),
        format!(
            r#"
{AUDITBEAT_YML}

output.logstash:
  hosts: ["localhost:5044"]
"#
        ),
    )?;

    system("systemctl enable jj-auditbeat")?;
    system("systemctl restart jj-auditbeat")?;

    println!("{}", "--- Auditbeat is set up".green());

    Ok(())
}

fn setup_filebeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up filebeat".green());

    std::fs::write(
        "/usr/lib/systemd/system/jj-filebeat.service",
        FILEBEAT_SERVICE.replace(
            "$FB_HOME",
            &format!("{}/filebeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for filebeat")?;

    let es_password = get_elastic_password(password)?;

    let fb_home = cpaths!(args.elastic_install_directory, "filebeat");

    apply_selinux_labels(
        &fb_home,
        &cpaths!(fb_home, "filebeat.yml"),
        &cpaths!(fb_home, "filebeat"),
    )?;

    std::fs::write(
        cpaths!(fb_home, "filebeat.yml"),
        format!(
            r#"
{FILEBEAT_YML}

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

output.elasticsearch:
  hosts: ["https://localhost:10200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "{}/http_ca.crt"
"#,
            args.elasticsearch_share_directory.display()
        )
        .replace(
            "$FILEBEAT_PATH",
            &format!("{}/filebeat", args.elastic_install_directory.display()),
        ),
    )?;

    system(&format!(
        "{0}/filebeat --path.home {0} --path.config {0} --path.data {0}/data --path.logs {0}/logs setup --modules iis,mysql,apache,nginx",
        fb_home.display()
    ))?;

    std::fs::write(
        cpaths!(fb_home, "filebeat.yml"),
        format!(
            r#"
{FILEBEAT_YML}

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
  hosts: ["localhost:5044"]
"#
        )
        .replace(
            "$FILEBEAT_PATH",
            &format!("{}/filebeat", args.elastic_install_directory.display()),
        ),
    )?;

    system("systemctl enable jj-filebeat")?;
    system("systemctl restart jj-filebeat")?;

    println!("{}", "--- Filebeat is set up".green());

    Ok(())
}

fn setup_packetbeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up packetbeat".green());

    std::fs::write(
        "/usr/lib/systemd/system/jj-packetbeat.service",
        PACKETBEAT_SERVICE.replace(
            "$PB_HOME",
            &format!("{}/packetbeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for packetbeat")?;

    let es_password = get_elastic_password(password)?;

    let pb_home = cpaths!(args.elastic_install_directory, "packetbeat");

    apply_selinux_labels(
        &pb_home,
        &cpaths!(pb_home, "packetbeat.yml"),
        &cpaths!(pb_home, "packetbeat"),
    )?;

    std::fs::write(
        cpaths!(pb_home, "packetbeat.yml"),
        format!(
            r#"
{PACKETBEAT_YML}

output.elasticsearch:
  hosts: ["https://localhost:10200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "{}/http_ca.crt"
"#,
            args.elasticsearch_share_directory.display()
        ),
    )?;

    system(&format!(
        "{0}/packetbeat --path.home {0} --path.config {0} --path.data {0}/data --path.logs {0}/logs setup",
        pb_home.display()
    ))?;

    std::fs::write(
        cpaths!(pb_home, "packetbeat.yml"),
        format!(
            r#"
{PACKETBEAT_YML}

output.logstash:
  hosts: ["localhost:5044"]
"#
        ),
    )?;

    system("systemctl enable jj-packetbeat")?;
    system("systemctl restart jj-packetbeat")?;

    println!("{}", "--- Packetbeat is set up".green());

    Ok(())
}

fn setup_winlogbeat(
    bb: &Busybox,
    password: &mut Option<String>,
    args: &ElkSubcommandArgs,
) -> eyre::Result<()> {
    println!(
        "{}",
        "--- Prepping Elasticsearch for Winlogbeat data".green()
    );

    let es_password = get_elastic_password(password)?;

    let cert = std::fs::read_to_string(cpaths!(args.elasticsearch_share_directory, "http_ca.crt"))?;
    let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;

    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()?;

    let public_ip = get_public_ip(bb)?;

    let winlogbeat_zip = std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(
        cpaths!(args.elasticsearch_share_directory, "winlogbeat.zip"),
    )?);
    let mut archive = zip::read::ZipArchive::new(winlogbeat_zip)?;

    fn visit_fields(
        mappings: &mut serde_json::Map<String, serde_json::Value>,
        object_chain: Option<&str>,
        field: serde_json::Value,
    ) {
        use serde_json::Value as V;

        // only returns None when object_chain is an empty string or when internal corruption happens
        fn resolve_chain<'a, 'b>(
            mappings: &'a mut serde_json::Map<String, serde_json::Value>,
            mut object_chain: impl Iterator<Item = &'b str>,
        ) -> Option<serde_json::map::Entry<'a>> {
            let mut current_entry = mappings.entry(object_chain.next()?);

            while let Some(part) = object_chain.next() {
                let new_mapping = current_entry.or_insert(serde_json::json!({
                    "properties": {}
                }));

                current_entry = new_mapping
                    .as_object_mut()?
                    .get_mut("properties")?
                    .as_object_mut()?
                    .entry(part);
            }

            Some(current_entry)
        }

        let V::Object(mut m) = field else {
            return;
        };

        m.remove("level");
        m.remove("description");
        m.remove("required");
        m.remove("example");
        m.remove("default_field");

        let Some(field_type) = m.get("type").and_then(V::as_str) else {
            return;
        };
        let Some(name) = m.get("name").and_then(V::as_str) else {
            return;
        };

        let Some(field_entry) = resolve_chain(
            mappings,
            object_chain
                .map_or(
                    Box::new(std::iter::empty()) as Box<dyn Iterator<Item = &str>>,
                    |s| Box::new(s.split('.')),
                )
                .chain(name.split('.')),
        ) else {
            return;
        };

        if field_type == "group" {
            let name = name.to_owned();

            let Some(V::Array(fields)) = m.remove("fields") else {
                return;
            };

            let new_chain = object_chain.map_or_else(|| name.to_owned(), |s| format!("{s}.{name}"));

            for field in fields {
                visit_fields(mappings, Some(&new_chain), field);
            }
        } else {
            field_entry.or_insert(m.into());
        }
    }

    println!("Parsing index template...");

    let fields_file = archive.by_name(&format!(
        "winlogbeat-{}-windows-x86_64/fields.yml",
        args.elastic_version
    ))?;

    let mut mappings = serde_json::Map::new();

    let fields_parsed = serde_yaml_ng::from_reader::<_, serde_json::Value>(fields_file)
        .context("Could not parse basic winlogbeat fields mappings")?;

    let transformed_fields = match fields_parsed {
        serde_json::Value::Array(a) => {
            for field in a {
                visit_fields(&mut mappings, None, field);
            }
        }
        _ => {
            eyre::bail!("Could not parse field mappings file to prepare index template");
        }
    };

    let index_template = serde_json::json!({
        "index_patterns": ["winlogbeat-*"],
        "data_stream": {},
        "template": {
            "settings": {
                "index.number_of_shards": 1,
                "index.lifecycle.name": "winlogbeat"
            },
            "mappings": {
                "properties": transformed_fields
            }
        }
    });

    let index_template_body = serde_json::to_string(&index_template)?;

    println!("Uploading index template...");

    let response = client
        .post(format!(
            "https://{public_ip}:10200/_index_template/winlogbeat-{}",
            args.elastic_version
        ))
        .basic_auth("elastic", Some(&es_password))
        .header("content-type", "application/json")
        .body(index_template_body)
        .send()
        .context("Could not contact elasticsearch server")?
        .json::<serde_json::Value>()
        .context("Could not parse response from elasticsearch")?;

    if response.get("acknowledged") == Some(&(true.into())) {
        println!("Successfully uploaded index template!");
    } else {
        eyre::bail!("Issues uploading index template: {response}");
    }

    println!("Done uploading index template! Creating data stream...");

    let response = client
        .put(format!(
            "https://{public_ip}:10200/_data_stream/winlogbeat-{}",
            args.elastic_version
        ))
        .basic_auth("elastic", Some(&es_password))
        .send()
        .context("Could not contact elasticsearch server")?
        .json::<serde_json::Value>()
        .context("Could not parse response from elasticsearch")?;

    if response.get("acknowledged") == Some(&(true.into())) {
        println!("Successfully uploaded index template!");
    } else {
        eyre::bail!("Issues uploading index template: {response}");
    }

    println!("Done creating data stream! Searching for ingest pipelines...");

    for i in 0..archive.len() {
        let file = match archive.by_index(i) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not search for winlogbeat ingest pipeline: {e}");
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

        let mut ingest_pipeline = match serde_yaml_ng::from_reader::<_, serde_json::Value>(file) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not process {file_name}: {e}");
                continue;
            }
        };

        if let Some(serde_json::Value::Array(processors)) = ingest_pipeline.get_mut("processors") {
            for processor in processors {
                if let Some(pipeline) = processor.get_mut("pipeline")
                    && let Some(name) = pipeline.get_mut("name")
                    && let serde_json::Value::String(name) = name
                    && let Some(inner_name) = name
                        .strip_suffix("\" >}")
                        .and_then(|s| s.strip_prefix("{< IngestPipeline \""))
                {
                    *name = format!("winlogbeat-{}-{inner_name}", args.elastic_version);
                }
            }
        }

        let ingest_pipeline_json = match serde_json::to_string(&ingest_pipeline) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not serialize pipeline {file_name} as JSON: {e}");
                continue;
            }
        };

        let Some(file_name) = file_name.rsplitn(2, '/').next() else {
            eprintln!("Could not extract file name from path");
            continue;
        };

        let pipeline_name = file_name.trim_end_matches(".yml");

        match client
            .put(format!(
                "https://{public_ip}:10200/_ingest/pipeline/winlogbeat-{}-{pipeline_name}",
                args.elastic_version
            ))
            .basic_auth("elastic", Some(&es_password))
            .header("content-type", "application/json")
            .body(ingest_pipeline_json)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(v) => {
                if let serde_json::Value::Object(ref o) = v
                    && o.get("acknowledged") == Some(&(true.into()))
                {
                    println!("Success!");
                } else {
                    eprintln!("Failed to import pipeline {pipeline_name}: {v}");
                }
            }
            Err(e) => {
                eprintln!("Failed to contact elasticsearch to import pipeline: {e}")
            }
        }
    }

    println!("{}", "--- Ready for Winlogbeat data".green());

    Ok(())
}

fn untar_beat(
    src_path: impl AsRef<Path> + AsRef<std::ffi::OsStr> + std::fmt::Debug,
    dest_path: impl AsRef<Path> + AsRef<std::ffi::OsStr> + std::fmt::Debug,
) -> eyre::Result<()> {
    std::fs::create_dir_all(&dest_path)?;
    let backing_file = File::open(src_path).context("Could not open file for decompression")?;
    let buffer = BufReader::new(backing_file);
    let decompress = GzDecoder::new(buffer);
    let mut archive = Archive::new(decompress);

    for entry in archive.entries()? {
        let mut entry = entry?;
        if let Some(parent) = entry.path()?.components().next()
            && let Ok(sub_path) = entry.path()?.strip_prefix(parent)
        {
            if let Some(parent) = sub_path.parent() {
                std::fs::create_dir_all(cpaths!(dest_path, parent))?;
            }
            entry.unpack(cpaths!(dest_path, sub_path))?;
        }
    }

    Ok(())
}

fn download_beats(download_shell: bool, args: &ElkBeatsArgs) -> eyre::Result<()> {
    println!("{}", "--- Downloading beats...".green());

    let mut download_threads = vec![];

    for beat in ["auditbeat", "filebeat", "packetbeat"] {
        let args = args.clone();
        let download_package = move || {
            let res = download_file(
                &format!(
                    "http://{}:{}/{}.tar.gz",
                    args.elk_ip, args.elk_share_port, beat
                ),
                format!("/tmp/{beat}.tar.gz"),
            );
            println!("Done downloading {beat}!");
            res
        };
        if download_shell {
            download_package()?;
        } else {
            download_threads.push(thread::spawn(download_package));
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

    Ok(())
}

fn install_beats(bb: &Busybox, args: &ElkBeatsArgs) -> eyre::Result<()> {
    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| download_beats(true, args))??;
    } else {
        download_beats(false, args)?;
    }

    println!("--- Done downloading beats packages! Installing beats packages...");

    let mut threads = Vec::new();

    for pkg in ["filebeat", "auditbeat", "packetbeat"] {
        let src_path = cpaths!("/tmp", format!("{pkg}.tar.gz"));
        let dest_path = cpaths!(args.elastic_install_directory, pkg);

        threads.push(thread::spawn(move || -> eyre::Result<()> {
            untar_beat(src_path, dest_path)?;
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
                    "!!! Could not join download thread due to panic!".red()
                );
            }
        }
    }

    for pkg in ["filebeat", "auditbeat", "packetbeat"] {
        let dest_path = cpaths!(args.elastic_install_directory, pkg);

        apply_selinux_labels(
            &dest_path,
            &cpaths!(dest_path, &format!("{pkg}.yml")),
            &cpaths!(dest_path, pkg),
        )?;
    }

    std::fs::write(
        "/usr/lib/systemd/system/jj-auditbeat.service",
        AUDITBEAT_SERVICE.replace(
            "$AB_HOME",
            &format!("{}/auditbeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for auditbeat")?;

    std::fs::write(
        "/usr/lib/systemd/system/jj-filebeat.service",
        FILEBEAT_SERVICE.replace(
            "$FB_HOME",
            &format!("{}/filebeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for filebeat")?;

    std::fs::write(
        "/usr/lib/systemd/system/jj-packetbeat.service",
        PACKETBEAT_SERVICE.replace(
            "$PB_HOME",
            &format!("{}/packetbeat", args.elastic_install_directory.display()),
        ),
    )
    .context("Could not write systemd service for packetbeat")?;

    println!(
        "{}",
        "--- Done installing beats! Configuring now...".green()
    );

    std::fs::write(
        cpaths!(args.elastic_install_directory, "auditbeat", "auditbeat.yml"),
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
"#,
            AUDITBEAT_YML, args.elk_ip
        ),
    )?;

    std::fs::write(
        cpaths!(args.elastic_install_directory, "filebeat", "filebeat.yml"),
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
"#,
            FILEBEAT_YML, args.elk_ip
        )
        .replace(
            "$FILEBEAT_PATH",
            &format!("{}/filebeat", args.elastic_install_directory.display()),
        ),
    )?;

    std::fs::write(
        cpaths!(
            args.elastic_install_directory,
            "packetbeat",
            "packetbeat.yml"
        ),
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
"#,
            PACKETBEAT_YML, args.elk_ip
        ),
    )?;

    println!("{}", "--- Done configuring beats!".green());

    if let Err(e) = disable_auditd() {
        eprintln!("Could not disable auditd: {e}");
    }

    println!("{}", "--- Verifying output".green());

    for beat in ["auditbeat", "packetbeat", "filebeat"] {
        Command::new(cpaths!(args.elastic_install_directory, beat, beat))
            .current_dir(cpaths!(args.elastic_install_directory, beat))
            .args(["test", "output"])
            .spawn()?
            .wait()?;
        system(&format!("systemctl enable jj-{beat}"))?;
        system(&format!("systemctl restart jj-{beat}"))?;
    }

    println!("--- All set up!");

    if !args.dont_install_suricata {
        install_suricata(
            bb,
            &SuricataInstallArgs {
                use_download_shell: args.use_download_shell,
                sneaky_ip: args.sneaky_ip,
            },
        )?;
    }

    Ok(())
}

fn install_suricata(bb: &Busybox, args: &SuricataInstallArgs) -> eyre::Result<()> {
    println!("{}", "--- Installing Suricata...".green());

    if qx("getenforce")?.1.contains("Enforcing") {
        println!("SELinux is enabled, fixing contexts...");
        system("restorecon -R /etc")?;
    }

    let distro = get_distro()?;
    let download_settings = args
        .use_download_shell
        .then_some(DownloadSettings::Container {
            name: None,
            sneaky_ip: args.sneaky_ip,
        })
        .unwrap_or(DownloadSettings::NoContainer);

    if distro.is_deb_based() {
        install_apt_packages(download_settings.clone(), &["suricata", "suricata-update"])?;
    } else if distro.is_rhel_based() {
        install_dnf_packages(
            download_settings.clone(),
            &["epel-release", "dnf-plugins-core"],
        )?;

        if args.use_download_shell {
            DownloadContainer::new(None, args.sneaky_ip)?
                .run(|| system("dnf copr enable -y @oisf/suricata-8.0"))??;
        } else {
            system("dnf copr enable -y @oisf/suricata-8.0")?;
        }

        install_dnf_packages(download_settings.clone(), &["suricata"])?;
    } else {
        println!("Cannot install Suricata on a non Debian or RHEL based system!");
        return Ok(());
    }

    if args.use_download_shell {
        DownloadContainer::new(None, args.sneaky_ip)?.run(|| system("suricata-update"))??;
    } else {
        system("suricata-update")?;
    }

    let routes = bb
        .execute(&["ip", "route"])
        .context("Could not query host routes")?;

    let default_dev = pcre!(&routes =~ m/r"default[^\n]*dev\s([^\s]+)"/xms)
        .get(0)
        .ok_or(eyre::eyre!("Could not find default route!"))?
        .extract::<1>()
        .1[0];

    std::fs::write(
        "/etc/suricata/suricata.yaml",
        SURICATA_YAML.replace("$INTERFACE", default_dev),
    )?;
    std::fs::write(
        "/etc/suricata/suricata.yml",
        SURICATA_YAML.replace("$INTERFACE", default_dev),
    )?;

    // default suricata configuration *forces* us to use eth0... but that doesn't exist
    if distro.is_rhel_based() {
        let _ = std::fs::read_to_string("/etc/sysconfig/suricata").and_then(|content| {
            std::fs::write(
                "/etc/sysconfig/suricata",
                content.replace("eth0", default_dev),
            )
        });
    } else {
        let _ = std::fs::read_to_string("/etc/default/suricata").and_then(|content| {
            std::fs::write(
                "/etc/sysconfig/suricata",
                content.replace("eth0", default_dev),
            )
        });
    }

    system("systemctl daemon-reload")?;
    system("systemctl enable suricata")?;
    system("systemctl start suricata")?;

    println!("{}", "--- Configured Suricata!".green());

    Ok(())
}
