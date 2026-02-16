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
use nix::unistd::chdir;

use crate::utils::{download_file, system};

use crate::{
    pcre,
    utils::{
        download_container::DownloadContainer,
        os_version::{Distro, get_distro},
        qx,
    },
};

// Defines a variable called KIBANA_DASHBOARDS of type &'static [&'static str]
// It includes all the ndjson files for kibana dashboards
include!(concat!(env!("OUT_DIR"), "/kibana_dashboards.rs"));

const FILEBEAT_YML: &str = include_str!("elk/filebeat.yml");
const AUDITBEAT_YML: &str = include_str!("elk/auditbeat.yml");
const PACKETBEAT_YML: &str = include_str!("elk/packetbeat.yml");
const LOGSTASH_CONF: &str = include_str!("elk/pipeline.conf");

#[derive(Parser, Clone, Debug)]
#[command(about)]
pub struct ElkSubcommandArgs {
    /// Version to use for Elasticsearch, Logstash, Kibana, Auditbeat, Filebeat, and Packetbeat
    #[arg(long, short = 'V', default_value = "9.2.0")]
    elastic_version: String,

    /// URL to download Elasticsearch, Logstash, and Kibana from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads")]
    download_url: String,

    /// URL to download Auditbeat, Filebeat, and Packetbeat from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads/beats")]
    beats_download_url: String,

    /// Where to put files to be shared on the network
    #[arg(long, short = 'S', default_value = "/opt/es")]
    elasticsearch_share_directory: PathBuf,

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
    /// Install Elasticsearch completely, running all other subcommands except beats
    #[command(visible_alias = "in")]
    Install(ElkSubcommandArgs),

    /// Setup ZRAM to provide 4G of swap based on compressed RAM
    #[command(visible_alias = "zr")]
    SetupZram(ElkSubcommandArgs),

    /// Download packages to install ELK for the current distribution and beats for both Debian and RHEL based distributions
    #[command(visible_alias = "dpkg")]
    DownloadPackages(ElkSubcommandArgs),

    /// Install ELK and beats on the current host
    #[command(visible_alias = "ipkg")]
    InstallPackages(ElkSubcommandArgs),

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

        let distro = get_distro()?;

        if !distro.is_rhel_or_deb_based() {
            eprintln!(
                "{}",
                "!!! ELK utilities can only be run on RHEL or Debian based distributions".red()
            );
            return Ok(());
        }

        if let EC::InstallBeats(args) = &self.command {
            return install_beats(&distro, args);
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
            download_packages(&distro, args)?;
        }

        if let EC::Install(args) | EC::InstallPackages(args) = &self.command {
            install_packages(&distro, args)?;
        }

        if let EC::Install(args) | EC::SetupElastic(args) = &self.command {
            setup_elasticsearch(&mut elastic_password, args)?;
        }

        if let EC::Install(_) | EC::SetupKibana(_) = &self.command {
            setup_kibana(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupLogstash(_) = &self.command {
            setup_logstash(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupAuditbeat(_) = &self.command {
            setup_auditbeat(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupFilebeat(_) = &self.command {
            setup_filebeat(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupPacketbeat(_) = &self.command {
            setup_packetbeat(&mut elastic_password)?;
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

fn download_packages(distro: &Distro, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    let download_packages_internal = || -> eyre::Result<()> {
        std::fs::create_dir_all(&args.elasticsearch_share_directory)?;

        let mut download_threads = vec![];

        println!("{}", "--- Downloading elastic packages...".green());

        if distro.is_deb_based() {
            for pkg in ["elasticsearch", "logstash", "kibana"] {
                let args = args.clone();
                let pkg = pkg.to_string();
                download_threads.push(thread::spawn(move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{pkg}.deb"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-amd64.deb",
                            args.download_url, pkg, pkg, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {pkg}!");
                    res
                }));
            }
        } else {
            for pkg in ["elasticsearch", "logstash", "kibana"] {
                let args = args.clone();
                let pkg = pkg.to_string();
                download_threads.push(thread::spawn(move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{pkg}.rpm"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-x86_64.rpm",
                            args.download_url, pkg, pkg, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {pkg}!");
                    res
                }));
            }
        }

        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            download_threads.push(thread::spawn({
                let args = args.clone();
                let beat = beat.to_string();

                move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{beat}.deb"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-amd64.deb",
                            args.beats_download_url, beat, beat, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {beat} deb!");
                    res
                }
            }));

            download_threads.push(thread::spawn({
                let args = args.clone();
                let beat = beat.to_string();

                move || {
                    let mut dest_path = args.elasticsearch_share_directory.clone();
                    dest_path.push(format!("{beat}.rpm"));
                    let res = download_file(
                        &format!(
                            "{}/{}/{}-{}-x86_64.rpm",
                            args.beats_download_url, beat, beat, args.elastic_version
                        ),
                        dest_path,
                    );
                    println!("Done downloading {beat} rpm!");
                    res
                }
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

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(download_packages_internal)??;
    } else {
        download_packages_internal()?;
    }

    println!(
        "{}",
        "--- Successfully downloaded elastic packages!".green()
    );

    Ok(())
}

fn install_packages(distro: &Distro, args: &ElkSubcommandArgs) -> eyre::Result<()> {
    chdir(&args.elasticsearch_share_directory)?;

    println!("{}", "--- Installing elastic packages...".green());

    if distro.is_deb_based() {
        for pkg in [
            "elasticsearch",
            "logstash",
            "kibana",
            "filebeat",
            "auditbeat",
            "packetbeat",
        ] {
            system(&format!("dpkg -i {pkg}.deb"))?;
        }
    } else {
        for pkg in [
            "elasticsearch",
            "logstash",
            "kibana",
            "filebeat",
            "auditbeat",
            "packetbeat",
        ] {
            system(&format!("rpm -i {pkg}.rpm"))?;
        }
    }

    println!("{}", "--- Installed elastic packages!".green());

    Ok(())
}

fn setup_elasticsearch(
    password: &mut Option<String>,
    args: &ElkSubcommandArgs,
) -> eyre::Result<()> {
    println!("{}", "--- Configuring Elasticsearch".green());

    system("systemctl enable elasticsearch")?;
    system("systemctl start elasticsearch")?;

    let elastic_password = get_elastic_password(password)?;

    let mut password_change =
        Command::new("/usr/share/elasticsearch/bin/elasticsearch-reset-password")
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

    std::fs::create_dir_all("/etc/es_certs")?;

    let mut perms = std::fs::metadata("/etc/elasticsearch/certs/http_ca.crt")?.permissions();
    perms.set_mode(0o444);

    std::fs::copy(
        "/etc/elasticsearch/certs/http_ca.crt",
        "/etc/es_certs/http_ca.crt",
    )?;
    let mut share_dir = args.elasticsearch_share_directory.clone();
    share_dir.push("http_ca.crt");
    std::fs::copy("/etc/elasticsearch/certs/http_ca.crt", &share_dir)?;

    std::fs::set_permissions("/etc/es_certs/http_ca.crt", perms.clone())?;
    std::fs::set_permissions(share_dir, perms)?;

    println!("{}", "--- Elasticsearch configured!".green());

    Ok(())
}

fn setup_kibana(password: &mut Option<String>) -> eyre::Result<()> {
    use reqwest::blocking::{
        Client,
        multipart::{Form, Part},
    };
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

    println!("{}", "--- Configuring Kibana".green());

    let elastic_password = get_elastic_password(password)?;

    let token =
        qx("/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana")?.1;

    system(&format!(
        "sudo -u kibana /usr/share/kibana/bin/kibana-setup -t {token}"
    ))?;

    let kibana_yml = std::fs::read_to_string("/etc/kibana/kibana.yml")?;
    let new_kibana_yml =
        pcre!(&kibana_yml =~ s/r"^[^\n]server.host:[^\n]+"/r#"server.host: "0.0.0.0""#/xms);
    std::fs::write("/etc/kibana/kibana.yml", new_kibana_yml)?;

    system("systemctl enable kibana")?;
    system("systemctl start kibana")?;

    println!("{}", "--- Waiting for Kibana...".green());

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

    println!("{}", "--- Kibana online! Importing dashboards...".green());

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

    println!("{}", "--- Kibana configured!".green());

    Ok(())
}

fn setup_logstash(password: &mut Option<String>) -> eyre::Result<()> {
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct ElasticApiKeys {
        id: String,
        name: String,
        api_key: String,
        encoded: String,
    }

    println!("{}", "--- Configuring Logstash...".green());

    std::fs::create_dir_all("/etc/systemd/system/logstash.service.d")?;

    if std::fs::metadata("/etc/systemd/system/logstash.service.d/api_key.conf").is_err() {
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
            .post("https://localhost:9200/_security/api_key")
            .basic_auth("elastic", Some(es_password))
            .header("kbn-xsrf", "true")
            .header("content-type", "application/json")
            .body(api_key_permissions_body)
            .send()?
            .json::<ElasticApiKeys>()?;

        std::fs::write(
            "/etc/systemd/system/logstash.service.d/api_key.conf",
            format!(
                r#"[Service]
Environment="ES_API_KEY={}:{}"
"#,
                api_keys.id, api_keys.api_key
            ),
        )?;
    }

    std::fs::write("/etc/logstash/conf.d/pipeline.conf", LOGSTASH_CONF)?;

    system("systemctl daemon-reload")?;
    system("systemctl enable logstash")?;
    system("systemctl restart logstash")?;

    println!("{}", "--- Logstash configured!".green());

    Ok(())
}

fn setup_auditbeat(password: &mut Option<String>) -> eyre::Result<()> {
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

fn setup_filebeat(password: &mut Option<String>) -> eyre::Result<()> {
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

fn setup_packetbeat(password: &mut Option<String>) -> eyre::Result<()> {
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

fn download_beats(distro: &Distro, args: &ElkBeatsArgs) -> eyre::Result<()> {
    println!("{}", "--- Downloading beats...".green());

    let mut download_threads = vec![];

    if distro.is_deb_based() {
        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            let args = args.clone();
            download_threads.push(thread::spawn(move || {
                let res = download_file(
                    &format!(
                        "http://{}:{}/{}.deb",
                        args.elk_ip, args.elk_share_port, beat
                    ),
                    format!("/tmp/{beat}.deb"),
                );
                println!("Done downloading {beat}!");
                res
            }));
        }
    } else {
        for beat in ["auditbeat", "filebeat", "packetbeat"] {
            let args = args.clone();
            download_threads.push(thread::spawn(move || {
                let res = download_file(
                    &format!(
                        "http://{}:{}/{}.rpm",
                        args.elk_ip, args.elk_share_port, beat
                    ),
                    format!("/tmp/{beat}.rpm"),
                );
                println!("Done downloading {beat}!");
                res
            }));
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

fn install_beats(distro: &Distro, args: &ElkBeatsArgs) -> eyre::Result<()> {
    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| download_beats(distro, args))??;
    } else {
        download_beats(distro, args)?;
    }

    println!("--- Done downloading beats packages! Installing beats packages...");

    for beat in ["auditbeat", "filebeat", "packetbeat"] {
        if distro.is_deb_based() {
            system(&format!("dpkg -i /tmp/{beat}.deb"))?;
        } else {
            system(&format!("rpm -i /tmp/{beat}.rpm"))?;
        }
    }

    println!(
        "{}",
        "--- Done installing beats! Configuring now...".green()
    );

    std::fs::write(
        "/etc/auditbeat/auditbeat.yml",
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
        "/etc/filebeat/filebeat.yml",
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
"#,
            FILEBEAT_YML, args.elk_ip
        ),
    )?;

    std::fs::write(
        "/etc/packetbeat/packetbeat.yml",
        format!(
            r#"
{}

output.logstash:
  hosts: ["{}:5044"]
"#,
            PACKETBEAT_YML, args.elk_ip
        ),
    )?;

    system("systemctl enable auditbeat")?;
    system("systemctl restart auditbeat")?;
    system("systemctl enable filebeat")?;
    system("systemctl restart filebeat")?;
    system("systemctl enable packetbeat")?;
    system("systemctl restart packetbeat")?;

    println!("{}", "--- Done configuring beats! Verifying output".green());

    system("auditbeat test output")?;
    system("filebeat test output")?;
    system("packetbeat test output")?;

    println!("--- All set up!");

    Ok(())
}
