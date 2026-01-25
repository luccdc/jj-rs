use std::{
    io::Write,
    net::Ipv4Addr,
    os::unix::fs::{PermissionsExt, chown},
    path::PathBuf,
    process::{Command, Stdio},
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::{Context, eyre};
use libc::getuid;

use crate::{
    pcre,
    utils::{
        busybox::Busybox,
        download_container::DownloadContainer,
        os_version::{Distro, get_distro},
        packages::{install_apt_packages, install_dnf_packages},
        passwd, qx, system,
    },
};

#[derive(Parser, Debug)]
#[command(about)]
pub struct WazuhSubcommandArgs {
    /// Version to use for Wazuh to download packages and install them
    #[arg(long, short = 'V', default_value = "4.14")]
    wazuh_version: String,

    /// Use the download container when downloading files to circumvent the host based firewall
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Use a specific IP address for source NAT when downloading through the container
    #[arg(long, short = 'I')]
    sneaky_ip: Option<Ipv4Addr>,

    /// Where will temporary files be downloaded and extracted
    #[arg(long, short = 'w', default_value = "/tmp/wazuh-install")]
    working_dir: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub struct WazuhAgentArgs {
    /// The IP address of the Wazuh cluster
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    wazuh_ip: Ipv4Addr,

    /// Whether or not this is the Wazuh server. Set to true if run as part of `wazuh install`
    #[arg(long, short = 'm')]
    wazuh_manager: bool,
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

    /// Install and configure a Wazuh agent for this system
    #[command(visible_alias = "ia")]
    InstallAgent(WazuhAgentArgs),
}

/// Install, configure, and manage Wazuh on this server
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Wazuh {
    #[command(subcommand)]
    command: WazuhCommands,
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

        if let WC::InstallAgent(args) = self.command {
            return install_wazuh_agent(args);
        }

        let hostname = qx("hostnamectl")?.1;
        if pcre!(&hostname =~ qr/r"Static\+hostname:\s\(unset\)"/xms) {
            eprintln!(
                "{}",
                "!!! Wazuh installation requires a hostname explicitly set".red()
            );
            return Ok(());
        }

        let busybox = Busybox::new()?;

        let mut new_pass = String::new();

        if let WC::Install(_) | WC::RotateCredentials = &self.command {
            print!("Enter the password for the admin user: ");
            std::io::stdout()
                .flush()
                .context("Could not display password prompt")?;
            std::io::stdin()
                .read_line(&mut new_pass)
                .context("Could not read password from user")?;
            new_pass = new_pass.trim().to_string();
        }

        if let WC::Install(_) | WC::SetupZram = &self.command
            && let Err(e) = setup_zram()
        {
            eprintln!("{}{e}", "??? Could not set up zram: ".yellow());
        }

        if let WC::Install(args) | WC::MakeWorkingDirectory(args) = &self.command {
            make_working_dir(&args)?;
        }

        if let WC::Install(args) | WC::DownloadFiles(args) = &self.command {
            download_files(&args, &distro)?;
        }

        if let WC::Install(args) | WC::GenerateBundle(args) = &self.command {
            generate_bundle(&args, &busybox)?;
        }

        if let WC::Install(args) | WC::UnpackBundle(args) = &self.command {
            unpack_bundle(&args, &busybox)?;
        }

        if let WC::Install(args) | WC::InstallIndexer(args) = &self.command {
            install_indexer(&args, &distro)?;
        }

        if let WC::Install(args) | WC::InstallServer(args) = &self.command {
            install_server(&args, &distro)?;
        }

        if let WC::Install(args) | WC::InstallFilebeat(args) = &self.command {
            install_filebeat(&args, &distro, &busybox)?;
        }

        if let WC::Install(args) | WC::InstallDashboard(args) = &self.command {
            install_dashboard(&args, &distro, &busybox)?;
        }

        if let WC::Install(_) | WC::RotateCredentials = &self.command {
            rotate_credentials(new_pass)?;
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
        println!("{}", "--- Skipping ZRAM setup".green());
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

fn make_working_dir(args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    std::fs::create_dir_all(&args.working_dir)?;

    println!("{}", "--- Working directory made".green());

    Ok(())
}

fn download_files(args: &WazuhSubcommandArgs, os: &Distro) -> eyre::Result<()> {
    println!("--- Downloading installer and packages...");

    let download_files_internal = || -> eyre::Result<()> {
        use std::os::unix::fs::PermissionsExt;

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

        Command::new("/bin/sh")
            .args([
                "-c",
                &format!(
                    "./wazuh-install.sh -dw {} -da x86_64",
                    if os.is_deb_based() { "deb" } else { "rpm" }
                ),
            ])
            .current_dir(&args.working_dir)
            .spawn()
            .context("Could not spawn sh")?
            .wait()
            .context("Could not wait for command to finish")?;

        Ok(())
    };

    if args.use_download_shell {
        let container = DownloadContainer::new(None, args.sneaky_ip)?;

        container.run(download_files_internal)??;
    } else {
        download_files_internal()?;
    }

    println!("{}", "--- Successfully downloaded Wazuh files!".green());

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

    bb.command("tar")
        .args(["xf", "wazuh-install-files.tar"])
        .current_dir(&args.working_dir)
        .spawn()
        .context("Could not spawn tar")?
        .wait()
        .context("Could not wait for tar to finish")?;

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

    if let Value::Mapping(top) = &mut filebeat_config
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

    for i in 0..5 {
        match std::fs::read_to_string("/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml") {
            Ok(v) => {
                dashboard_config_2 = Some(v);
                break;
            }
            Err(e) => {
                eprintln!(
                    "Attempt {}; Error waiting for wazuh dashboard to generate configuration file: {e}",
                    i + 1
                );
                std::thread::sleep(std::time::Duration::from_secs(3));
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

    Ok(())
}

fn rotate_credentials(new_pass: String) -> eyre::Result<()> {
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

    Ok(())
}

fn cleanup(args: &WazuhSubcommandArgs) -> eyre::Result<()> {
    println!("--- Performing cleanup of Wazuh installation directory");

    std::fs::remove_dir_all(&args.working_dir)?;

    println!(
        "{}",
        "--- Successfully cleaned temporary working directory".green()
    );

    Ok(())
}

fn install_wazuh_agent(_args: WazuhAgentArgs) -> eyre::Result<()> {
    todo!()
}

fn get_public_ip(bb: &Busybox) -> eyre::Result<String> {
    let routes = bb
        .execute(&["ip", "route"])
        .context("Could not query host routes")?;

    let ips = bb
        .execute(&["ip", "addr"])
        .context("Could not query host addresses")?;

    let default_dev = pcre!(&routes =~ m/r"default[^\n]*dev\s([^\s]+)"/xms)
        .get(0)
        .ok_or(eyre!("Could not find default route!"))?
        .extract::<1>()
        .1[0];

    Ok(
        pcre!(&ips =~ m{r"^[0-9]+:\s" default_dev r":\s.*?inet\s([^\s]+)"}xms)
            .get(0)
            .ok_or(eyre!("Could not find associated IP!"))?
            .extract::<1>()
            .1[0]
            .to_string(),
    )
}
