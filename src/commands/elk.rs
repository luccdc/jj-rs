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

use crate::utils::{busybox::Busybox, download_file, system};

use crate::{
    pcre,
    utils::{download_container::DownloadContainer, os_version::Distro, passwd, qx},
};

// Defines a variable called KIBANA_DASHBOARDS of type &'static [&'static str]
// It includes all the ndjson files for kibana dashboards
include!(concat!(env!("OUT_DIR"), "/kibana_dashboards.rs"));

const FILEBEAT_YML: &str = include_str!("elk/filebeat.yml");
const AUDITBEAT_YML: &str = include_str!("elk/auditbeat.yml");
const PACKETBEAT_YML: &str = include_str!("elk/packetbeat.yml");
const LOGSTASH_CONF: &str = include_str!("elk/pipeline.conf");
const ELASTICSEARCH_SERVICE: &str = include_str!("elk/elasticsearch.service");
const KIBANA_SERVICE: &str = include_str!("elk/kibana.service");
const LOGSTASH_SERVICE: &str = include_str!("elk/logstash.service");

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

    /// Install beats and configure the system to send logs to the ELK stack
    #[command(visible_alias = "beats")]
    InstallBeats(ElkBeatsArgs),
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

        if !qx("systemctl --version")?.1.contains("systemd") {
            eprintln!("{}", "!!! ELK utilities require systemd to run".red());
            return Ok(());
        }

        if let EC::InstallBeats(args) = &self.command {
            return Ok(());
            // return install_beats(args);
        }

        let busybox = Busybox::new()?;

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
            setup_kibana(&busybox, &mut elastic_password, args)?;
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
                    println!("Done downloading {beat}!");
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

    for pkg in [
        "elasticsearch",
        "logstash",
        "kibana",
        "filebeat",
        "auditbeat",
        "packetbeat",
    ] {
        let src_path = cpaths!(args.elasticsearch_share_directory, format!("{pkg}.tar.gz"));
        let sub_path = format!("{pkg}-{}", args.elastic_version);
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
            "elasticsearch",
            "-S",
            "-H",
            "-D",
            "jj-elasticsearch",
        ])
        .output()?;

    if qx("getenforce")?.1.contains("Enforcing") {
        println!("SELinux is enabled, configuring contexts...");

        std::fs::create_dir_all(cpaths!(&es_home, "logs"))?;
        std::fs::create_dir_all(cpaths!(&es_home, "data"))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t usr_t {}",
            es_home.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t usr_t -R {}",
            es_home.display()
        ))?;
        system(&format!("restorecon -R {}", es_home.display()))?;

        let logs = cpaths!(es_home, "logs");
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
            es_path_conf.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t etc_t -R {}",
            es_path_conf.display()
        ))?;
        system(&format!("restorecon -R {}", es_path_conf.display()))?;

        let data = cpaths!(es_home, "data");
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

        let Ok(res) = dbg!(client.get("https://localhost:10200/_cluster/health").send()) else {
            continue;
        };
        let Ok(json) = dbg!(res.json::<ElasticStatus>()) else {
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
    std::fs::create_dir_all("/etc/es_certs")?;

    let perms: Permissions = PermissionsExt::from_mode(0o444);

    std::fs::copy(
        cpaths!(es_path_conf, "certs", "http_ca.crt"),
        "/etc/es_certs/http_ca.crt",
    )?;
    let share_dir = cpaths!(args.elasticsearch_share_directory, "http_ca.crt");
    std::fs::copy(cpaths!(es_path_conf, "certs", "http_ca.crt"), &share_dir)?;

    std::fs::set_permissions("/etc/es_certs/http_ca.crt", perms.clone())?;
    std::fs::set_permissions(share_dir, perms)?;

    println!("{}", "--- Elasticsearch configured!".green());

    Ok(())
}

fn setup_kibana(
    bb: &Busybox,
    password: &mut Option<String>,
    args: &ElkSubcommandArgs,
) -> eyre::Result<()> {
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

    if qx("getenforce")?.1.contains("Enforcing") {
        println!("SELinux is enabled, configuring contexts...");

        std::fs::create_dir_all(cpaths!(kbn_home, "logs"))?;
        std::fs::create_dir_all(cpaths!(kbn_home, "data"))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t usr_t {}",
            kbn_home.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t usr_t -R {}",
            kbn_home.display()
        ))?;
        system(&format!("restorecon -R {}", kbn_home.display()))?;

        let logs = cpaths!(kbn_home, "logs");
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
            kbn_path_conf.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t etc_t -R {}",
            kbn_path_conf.display()
        ))?;
        system(&format!("restorecon -R {}", kbn_path_conf.display()))?;

        let data = cpaths!(kbn_home, "data");
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

    let elastic_password = get_elastic_password(password)?;

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

    let keys_regex = regex::Regex::new("(?ms)(^xpack\\.[^:]+: [^\n]+)").unwrap();
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

        loop {
            println!("Waiting for Kibana...");
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

    println!("{}", "--- Kibana online! Importing dashboards...".green());

    {
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
    }

    println!("{}", "--- Kibana configured!".green());

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

    if qx("getenforce")?.1.contains("Enforcing") {
        println!("SELinux is enabled, configuring contexts...");

        std::fs::create_dir_all(cpaths!(ls_home, "logs"))?;
        std::fs::create_dir_all(cpaths!(ls_home, "data"))?;

        system(&format!(
            "semanage fcontext -a -s system_u -t usr_t {}",
            ls_home.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t usr_t -R {}",
            ls_home.display()
        ))?;
        system(&format!("restorecon -R {}", ls_home.display()))?;

        let logs = cpaths!(ls_home, "logs");
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
            ls_path_conf.display()
        ))?;
        system(&format!(
            "chcon -u system_u -t etc_t -R {}",
            ls_path_conf.display()
        ))?;
        system(&format!("restorecon -R {}", ls_path_conf.display()))?;

        let data = cpaths!(ls_home, "data");
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
                "names": ["filebeat-*","winlogbeat-*","auditbeat-*","packetbeat-*","logs-*"],
                "privileges": ["view_index_metadata","read","create","manage","manage_ilm"]
            }]
        }
    }
}
"#;

        let cert = std::fs::read_to_string("/etc/es_certs/http_ca.crt")?;
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
            "- pipeline.id: main\n  path.config: {}/*.conf",
            cpaths!(ls_path_conf, "conf.d").display()
        ),
    )?;
    std::fs::write(
        cpaths!(ls_path_conf, "conf.d", "pipeline.conf"),
        LOGSTASH_CONF,
    )?;

    system("systemctl daemon-reload")?;
    system("systemctl enable jj-logstash")?;
    system("systemctl restart jj-logstash")?;

    println!("{}", "--- Logstash configured!".green());

    Ok(())
}

fn setup_auditbeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up auditbeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/auditbeat/auditbeat.yml",
        format!(
            r#"
{AUDITBEAT_YML}

output.elasticsearch:
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#
        ),
    )?;

    system("auditbeat setup")?;

    std::fs::write(
        "/etc/auditbeat/auditbeat.yml",
        format!(
            r#"
{AUDITBEAT_YML}

output.logstash:
  hosts: ["localhost:5044"]
"#
        ),
    )?;

    system("systemctl enable auditbeat")?;
    system("systemctl restart auditbeat")?;

    println!("{}", "--- Auditbeat is set up".green());

    Ok(())
}

fn setup_filebeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up filebeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/filebeat/filebeat.yml",
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
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#
        ),
    )?;

    system("filebeat setup")?;

    std::fs::write(
        "/etc/filebeat/filebeat.yml",
        format!(
            r#"
{FILEBEAT_YML}

  - module: netflow
    log:
      enabled: true
      var:
        netflow_host: localhost
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
        ),
    )?;

    system("systemctl enable filebeat")?;
    system("systemctl restart filebeat")?;

    println!("{}", "--- Filebeat is set up".green());

    Ok(())
}

fn setup_packetbeat(password: &mut Option<String>, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    println!("{}", "--- Setting up packetbeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/packetbeat/packetbeat.yml",
        format!(
            r#"
{PACKETBEAT_YML}

output.elasticsearch:
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{es_password}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#
        ),
    )?;

    system("packetbeat setup")?;

    std::fs::write(
        "/etc/packetbeat/packetbeat.yml",
        format!(
            r#"
{PACKETBEAT_YML}

output.logstash:
  hosts: ["localhost:5044"]
"#
        ),
    )?;

    system("systemctl enable packetbeat")?;
    system("systemctl restart packetbeat")?;

    println!("{}", "--- Packetbeat is set up".green());

    Ok(())
}

fn download_beats(download_shell: bool, distro: &Distro, args: &ElkBeatsArgs) -> eyre::Result<()> {
    println!("{}", "--- Downloading beats...".green());

    let mut download_threads = vec![];

    if distro.is_deb_based() {
        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            let args = args.clone();
            let download_package = move || {
                let res = download_file(
                    &format!(
                        "http://{}:{}/{}.deb",
                        args.elk_ip, args.elk_share_port, beat
                    ),
                    format!("/tmp/{beat}.deb"),
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
    } else {
        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            let args = args.clone();
            let download_package = move || {
                let res = download_file(
                    &format!(
                        "http://{}:{}/{}.rpm",
                        args.elk_ip, args.elk_share_port, beat
                    ),
                    format!("/tmp/{beat}.rpm"),
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

// fn install_beats(args: &ElkBeatsArgs) -> eyre::Result<()> {
//     if args.use_download_shell {
//         let container = DownloadContainer::new(None, args.sneaky_ip)?;

//         container.run(|| download_beats(true, args))??;
//     } else {
//         download_beats(false, args)?;
//     }

//     println!("--- Done downloading beats packages! Installing beats packages...");

//     for beat in ["auditbeat", "filebeat", "packetbeat"] {
//         if distro.is_deb_based() {
//             system(&format!("dpkg -i /tmp/{beat}.deb"))?;
//         } else {
//             system(&format!("rpm -i /tmp/{beat}.rpm"))?;
//         }
//     }

//     println!(
//         "{}",
//         "--- Done installing beats! Configuring now...".green()
//     );

//     std::fs::write(
//         "/etc/auditbeat/auditbeat.yml",
//         format!(
//             r#"
// {}

// output.logstash:
//   hosts: ["{}:5044"]
// "#,
//             AUDITBEAT_YML, args.elk_ip
//         ),
//     )?;

//     std::fs::write(
//         "/etc/filebeat/filebeat.yml",
//         format!(
//             r#"
// {}

// output.logstash:
//   hosts: ["{}:5044"]
// "#,
//             FILEBEAT_YML, args.elk_ip
//         ),
//     )?;

//     std::fs::write(
//         "/etc/packetbeat/packetbeat.yml",
//         format!(
//             r#"
// {}

// output.logstash:
//   hosts: ["{}:5044"]
// "#,
//             PACKETBEAT_YML, args.elk_ip
//         ),
//     )?;

//     system("systemctl enable auditbeat")?;
//     system("systemctl restart auditbeat")?;
//     system("systemctl enable filebeat")?;
//     system("systemctl restart filebeat")?;
//     system("systemctl enable packetbeat")?;
//     system("systemctl restart packetbeat")?;

//     println!("{}", "--- Done configuring beats! Verifying output".green());

//     system("auditbeat test output")?;
//     system("filebeat test output")?;
//     system("packetbeat test output")?;

//     println!("--- All set up!");

//     Ok(())
// }
