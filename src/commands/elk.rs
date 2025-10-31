use std::process::{Command, Stdio};
use std::{
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    thread,
};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use colored::Colorize;
use nix::unistd::chdir;

use crate::utils::{download_file, system};

use crate::{
    pcre,
    utils::{
        distro::{Distro, get_distro},
        download_container::DownloadContainer,
        qx,
    },
};

// Defines a variable called KIBANA_DASHBOARDS of type &'static [&'static str]
// It includes all the ndjson files for kibana dashboards
include!(concat!(env!("OUT_DIR"), "/kibana_dashboards.rs"));

const FILEBEAT_YML: &'static str = include_str!("elk/filebeat.yml");
const AUDITBEAT_YML: &'static str = include_str!("elk/auditbeat.yml");
const PACKETBEAT_YML: &'static str = include_str!("elk/packetbeat.yml");
const LOGSTASH_CONF: &'static str = include_str!("elk/pipeline.conf");

#[derive(Parser, Clone, Debug)]
#[command(about)]
pub struct ElkSubcommandArgs {
    #[arg(long, short = 'V', default_value = "9.2.0")]
    elastic_version: String,

    #[arg(long, default_value = "https://artifacts.elastic.co/downloads")]
    download_url: String,

    #[arg(long, default_value = "https://artifacts.elastic.co/downloads/beats")]
    beats_download_url: String,

    #[arg(long, short = 'S', default_value = "/opt/es")]
    elasticsearch_share_directory: PathBuf,

    #[arg(long, short = 'd')]
    use_download_shell: bool,

    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,
}

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
pub struct ElkBeatsArgs {
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    elk_ip: Ipv4Addr,

    #[arg(long, short = 'p', default_value_t = 8080)]
    elk_share_port: u16,

    #[arg(long, short = 'd')]
    use_download_shell: bool,

    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,
}

#[derive(Subcommand, Debug)]
pub enum ElkCommands {
    #[command(visible_alias = "in")]
    Install(ElkSubcommandArgs),

    #[command(visible_alias = "zr")]
    SetupZram(ElkSubcommandArgs),

    #[command(visible_alias = "dpkg")]
    DownloadPackages(ElkSubcommandArgs),

    #[command(visible_alias = "ipkg")]
    InstallPackages(ElkSubcommandArgs),

    #[command(visible_alias = "es")]
    SetupElastic(ElkSubcommandArgs),

    #[command(visible_alias = "ki")]
    SetupKibana(ElkSubcommandArgs),

    #[command(visible_alias = "lo")]
    SetupLogstash(ElkSubcommandArgs),

    #[command(visible_alias = "ab")]
    SetupAuditbeat(ElkSubcommandArgs),

    #[command(visible_alias = "pb")]
    SetupPacketbeat(ElkSubcommandArgs),

    #[command(visible_alias = "fb")]
    SetupFilebeat(ElkSubcommandArgs),

    #[command(visible_alias = "beats")]
    InstallBeats(ElkBeatsArgs),
}

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Elk {
    #[command(subcommand)]
    command: ElkCommands,
}

impl super::Command for Elk {
    fn execute(self) -> anyhow::Result<()> {
        let Some(distro) = get_distro()? else {
            eprintln!("{}", "!!! Could not identify distribution to run on! This utility depends on being able to use package managers".red());
            return Ok(());
        };

        if !matches!(distro, Distro::Debian | Distro::RedHat) {
            eprintln!(
                "{}",
                "!!! ELK utilities can only be run on RHEL or Debian based distributions".red()
            );
            return Ok(());
        }

        use ElkCommands as EC;

        if let EC::InstallBeats(args) = &self.command {
            return install_beats(distro, &args);
        }

        let hostname = qx("hostnamectl")?.1;
        if pcre!(&hostname =~ qr/r"Static\+hostname:\s+\(unset\)"/xms) {
            eprintln!(
                "{}",
                "!!! ELK requires a hostname explicitly set to work correctly"
            );
            return Ok(());
        }

        let mut elastic_password = None;

        if let EC::Install(_) = &self.command {
            get_elastic_password(&mut elastic_password)?;
        }

        if let EC::Install(_) | EC::SetupZram(_) = &self.command {
            if let Err(e) = setup_zram() {
                eprintln!("{}{e}", "??? Could not set up zram: ".yellow());
            }
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

fn get_elastic_password(password: &mut Option<String>) -> anyhow::Result<String> {
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

fn setup_zram() -> anyhow::Result<()> {
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

fn download_packages(distro: &Distro, args: &ElkSubcommandArgs) -> anyhow::Result<()> {
    let download_packages_internal = || -> anyhow::Result<()> {
        std::fs::create_dir_all(&args.elasticsearch_share_directory)?;

        let mut download_threads = vec![];

        println!("{}", "--- Downloading elastic packages...".green());

        if *distro == Distro::Debian {
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
            };
        }

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| download_packages_internal())??;
    } else {
        download_packages_internal()?;
    }

    println!(
        "{}",
        "--- Successfully downloaded elastic packages!".green()
    );

    Ok(())
}

fn install_packages(distro: &Distro, args: &ElkSubcommandArgs) -> anyhow::Result<()> {
    chdir(&args.elasticsearch_share_directory)?;

    println!("{}", "--- Installing elastic packages...".green());

    if *distro == Distro::Debian {
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
) -> anyhow::Result<()> {
    println!("{}", "--- Configuring Elasticsearch".green());

    system("systemctl enable elasticsearch")?;
    system("systemctl start elasticsearch")?;

    let elastic_password = get_elastic_password(password)?;

    let mut password_change =
        Command::new("/usr/share/elasticsearch/bin/elasticsearch-reset-password")
            .args(&["-u", "elastic", "-i"])
            .stdin(Stdio::piped())
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .spawn()?;

    if let Some(ref mut stdin) = password_change.stdin {
        write!(stdin, "y\n")?;
        write!(stdin, "{}\n", elastic_password)?;
        write!(stdin, "{}\n", elastic_password)?;
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

fn setup_kibana(password: &mut Option<String>) -> anyhow::Result<()> {
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

fn setup_logstash(password: &mut Option<String>) -> anyhow::Result<()> {
    println!("{}", "--- Configuring Logstash...".green());

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct ElasticApiKeys {
        id: String,
        name: String,
        api_key: String,
        encoded: String,
    }

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

fn setup_auditbeat(password: &mut Option<String>) -> anyhow::Result<()> {
    println!("{}", "--- Setting up auditbeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/auditbeat/auditbeat.yml",
        format!(
            r#"
{}

output.elasticsearch:
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#,
            AUDITBEAT_YML, es_password
        ),
    )?;

    system("auditbeat setup")?;

    std::fs::write(
        "/etc/auditbeat/auditbeat.yml",
        format!(
            r#"
{}

output.logstash:
  hosts: ["localhost:5044"]
"#,
            AUDITBEAT_YML
        ),
    )?;

    system("systemctl enable auditbeat")?;
    system("systemctl restart auditbeat")?;

    println!("{}", "--- Auditbeat is set up".green());

    Ok(())
}

fn setup_filebeat(password: &mut Option<String>) -> anyhow::Result<()> {
    println!("{}", "--- Setting up filebeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/filebeat/filebeat.yml",
        format!(
            r#"
{}

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

output.elasticsearch:
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#,
            FILEBEAT_YML, es_password
        ),
    )?;

    system("filebeat setup")?;

    std::fs::write(
        "/etc/filebeat/filebeat.yml",
        format!(
            r#"
{}

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
"#,
            FILEBEAT_YML
        ),
    )?;

    system("systemctl enable filebeat")?;
    system("systemctl restart filebeat")?;

    println!("{}", "--- Filebeat is set up".green());

    Ok(())
}

fn setup_packetbeat(password: &mut Option<String>) -> anyhow::Result<()> {
    println!("{}", "--- Setting up packetbeat".green());

    let es_password = get_elastic_password(password)?;

    std::fs::write(
        "/etc/packetbeat/packetbeat.yml",
        format!(
            r#"
{}

output.elasticsearch:
  hosts: ["https://localhost:9200"]
  transport: https
  username: elastic
  password: "{}"
  ssl:
    enabled: true
    certificate_authorities: "/etc/es_certs/http_ca.crt"
"#,
            PACKETBEAT_YML, es_password
        ),
    )?;

    system("packetbeat setup")?;

    std::fs::write(
        "/etc/packetbeat/packetbeat.yml",
        format!(
            r#"
{}

output.logstash:
  hosts: ["localhost:5044"]
"#,
            PACKETBEAT_YML
        ),
    )?;

    system("systemctl enable packetbeat")?;
    system("systemctl restart packetbeat")?;

    println!("{}", "--- Packetbeat is set up".green());

    Ok(())
}

fn download_beats(distro: &Distro, args: &ElkBeatsArgs) -> anyhow::Result<()> {
    println!("{}", "--- Downloading beats...".green());

    let mut download_threads = vec![];

    if *distro == Distro::Debian {
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
        };
    }

    Ok(())
}

fn install_beats(distro: Distro, args: &ElkBeatsArgs) -> anyhow::Result<()> {
    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(|| download_beats(&distro, args))??;
    } else {
        download_beats(&distro, args)?;
    }

    println!(
        "{}",
        "--- Done downloading beats packages! Installing beats packages..."
    );

    for beat in ["auditbeat", "filebeat", "packetbeat"] {
        if distro == Distro::Debian {
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

    println!("{}", "--- All set up!");

    Ok(())
}
