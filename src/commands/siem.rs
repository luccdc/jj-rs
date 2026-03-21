use std::{
    io::{self, Write},
    net::Ipv4Addr,
    path::PathBuf,
};

use clap::Parser;
use colored::Colorize;
use eyre::Context;

use crate::{pcre, utils::qx};

#[derive(Parser, Clone, Debug)]
#[command(about)]
pub struct SiemSetup {
    /// Version to use for Elasticsearch, Logstash, Kibana, Auditbeat, Filebeat, and Packetbeat
    #[arg(long, short = 'S', default_value = "9.3.0")]
    elastic_version: String,

    /// Version to use for Wazuh to download packages and install them
    #[arg(long, short = 'W', default_value = "4.14")]
    wazuh_version: String,

    /// URL to download Elasticsearch, Logstash, and Kibana from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads")]
    elastic_download_url: String,

    /// URL to download Auditbeat, Filebeat, and Packetbeat from
    #[arg(long, default_value = "https://artifacts.elastic.co/downloads/beats")]
    elastic_beats_download_url: String,

    /// Where to put files to be shared on the network
    #[arg(long, short = 's', default_value = "/opt/es-share")]
    elasticsearch_share_directory: PathBuf,

    /// Where to install and configure everything ELK related, including beats
    #[arg(long, short = 'e', default_value = "/opt/jj-es")]
    elastic_install_directory: PathBuf,

    /// Where Elasticsearch should put its data directory
    #[arg(long, default_value = "/opt/jj-es/elasticsearch/data")]
    elasticsearch_data_directory: PathBuf,

    /// Disable syslog input
    #[arg(long, short = 'D')]
    disable_syslog: bool,

    /// Syslog input port for Filebeat
    #[arg(long, short = 'l', default_value = "1514")]
    syslog_port: u16,

    /// Public IP before NAT of Logstash
    #[arg(long, short)]
    nat_ip: Option<Ipv4Addr>,

    /// The size of the zram swap area, in gigabytes
    #[arg(long, short, default_value = "4")]
    zram_size: u8,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,

    /// Where will temporary files be downloaded and extracted for Wazuh
    #[arg(long, short = 'w', default_value = "/tmp/wazuh-working-dir")]
    wazuh_working_dir: PathBuf,
}

impl super::Command for SiemSetup {
    fn execute(self) -> eyre::Result<()> {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("{}", "!!! This script requires you to run as root".red());
            return Ok(());
        }

        if !qx("systemctl --version")?.1.contains("systemd") {
            eprintln!("{}", "!!! ELK utilities require systemd to run".red());
            return Ok(());
        }

        let busybox = crate::utils::busybox::Busybox::new()?;
        let distro = crate::utils::os_version::get_distro()?;

        if !distro.is_rhel_or_deb_based() {
            eprintln!(
                "{}",
                "!!! Wazuh utilities can only be run on RHEL or Debian".red()
            );
            return Ok(());
        }

        let hostname = qx("hostnamectl")?.1;
        if pcre!(&hostname =~ qr/r"Static\+hostname:\s+\(unset\)"/xms) {
            eprintln!("!!! ELK requires a hostname explicitly set to work correctly");
            return Ok(());
        }

        let mut elastic_pass = String::new();

        print!("Enter the password for the elastic user: ");
        io::stdout()
            .flush()
            .context("Could not display password prompt")?;
        io::stdin()
            .read_line(&mut elastic_pass)
            .context("Could not read password from user")?;
        elastic_pass = elastic_pass.trim().to_string();

        let mut wazuh_pass = String::new();

        print!("Enter the password for the Wazuh admin user: ");
        io::stdout()
            .flush()
            .context("Could not display password prompt")?;
        io::stdin()
            .read_line(&mut wazuh_pass)
            .context("Could not read password from user")?;
        wazuh_pass = wazuh_pass.trim().to_string();

        let mut elastic_password_option = Some(elastic_pass.clone());
        super::elk::Elk {
            command: super::elk::ElkCommands::Install(super::elk::ElkSubcommandArgs {
                beats_download_url: self.elastic_beats_download_url,
                disable_syslog: self.disable_syslog,
                download_url: self.elastic_download_url,
                elastic_install_directory: self.elastic_install_directory.clone(),
                elastic_version: self.elastic_version.clone(),
                elasticsearch_share_directory: self.elasticsearch_share_directory.clone(),
                elasticsearch_data_directory: self.elasticsearch_data_directory,
                nat_ip: self.nat_ip,
                zram_size: self.zram_size,
                sneaky_ip: self.sneaky_ip,
                syslog_port: self.syslog_port,
                use_download_shell: self.use_download_shell,
            }),
        }
        .execute_pipeline(&busybox, &mut elastic_password_option)?;

        std::fs::remove_file(
            self.elasticsearch_share_directory
                .join("elasticsearch.tar.gz"),
        )?;
        std::fs::remove_file(self.elasticsearch_share_directory.join("logstash.tar.gz"))?;
        std::fs::remove_file(self.elasticsearch_share_directory.join("kibana.tar.gz"))?;

        super::wazuh::Wazuh {
            command: super::wazuh::WazuhCommands::Install(super::wazuh::WazuhSubcommandArgs {
                jj_elastic_location: self.elastic_install_directory,
                jj_elastic_share_location: self.elasticsearch_share_directory,
                jj_elastic_version: self.elastic_version,
                sneaky_ip: self.sneaky_ip,
                use_download_shell: self.use_download_shell,
                wazuh_version: self.wazuh_version,
                working_dir: self.wazuh_working_dir,
                independent_logstash_install: false,
                beats_download_url: "https://artifacts.elastic.co/downloads/beats".into(),
                download_url: "https://artifacts.elastic.co/downloads".into(),
                public_nat_ip: self.nat_ip,
                dont_install_suricata: false,
            }),
        }
        .execute_pipeline(&distro, &busybox, &wazuh_pass, &elastic_pass)?;

        println!(
            "
Configuration Notes:
    When Installing and configuring ELK and Wazuh, the following ports should be opened up:
        - 443/tcp: Wazuh web interface
        - 514/udp: Syslog input. Generic from Windows and Linux systems
        - 1514/tcp: Agent communication for Wazuh
        - 1515/tcp: Agent enrollment for Wazuh
        - 2055/udp: Netflow input. Useful from network firewalls
        - 5044/tcp: Beats input from endpoints
        - 5601/tcp: Kibana web interface
        - 8080/tcp: Python web server for distributing certificate
        - 9001/udp: Palo Alto Syslog input
        - 9002/udp: Cisco FTD Syslog input
"
        );

        Ok(())
    }
}
