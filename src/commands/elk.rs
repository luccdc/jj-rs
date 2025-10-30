use std::{io, net::Ipv4Addr, path::PathBuf, thread};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use colored::Colorize;
use nix::unistd::chdir;

use crate::utils::{download_file, system};

use crate::{
    pcre,
    utils::{
        busybox::Busybox,
        distro::{Distro, get_distro},
        download_container::DownloadContainer,
        qx,
    },
};

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

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct ElkBeatsArgs {
    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    elk_ip: Ipv4Addr,

    #[arg(long, short = 'p', default_value_t = 8080)]
    elk_share_port: u16,
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

        let busybox = Busybox::new()?;

        use ElkCommands as EC;

        if let EC::InstallBeats(args) = &self.command {
            return install_beats(&busybox, distro, &args);
        }

        let mut elastic_password = None;

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
            setup_elasticsearch(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupKibana(args) = &self.command {
            setup_kibana(&busybox, args)?;
        }

        if let EC::Install(args) | EC::SetupLogstash(args) = &self.command {
            setup_logstash(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupAuditbeat(args) = &self.command {
            setup_auditbeat(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupFilebeat(args) = &self.command {
            setup_filebeat(&busybox, &mut elastic_password, args)?;
        }

        if let EC::Install(args) | EC::SetupPacketbeat(args) = &self.command {
            setup_packetbeat(&busybox, &mut elastic_password, args)?;
        }

        Ok(())
    }
}

fn get_elastic_password(bb: &Busybox, password: &mut Option<String>) -> anyhow::Result<String> {
    if let Some(pass) = password.clone() {
        return Ok(pass);
    }

    let mut new_pass = String::new();

    let _ = bb.execute(&["stty", "-echo"]);
    print!("Enter the password for the elastic user: ");
    io::stdin()
        .read_line(&mut new_pass)
        .context("Could not read password from user")?;
    new_pass = new_pass.trim().to_string();
    let _ = bb.execute(&["stty", "echo"]);

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
    _bb: &Busybox,
    _password: &mut Option<String>,
    _args: &ElkSubcommandArgs,
) -> anyhow::Result<()> {
    todo!()
}

fn setup_kibana(_bb: &Busybox, _args: &ElkSubcommandArgs) -> anyhow::Result<()> {
    todo!()
}

fn setup_logstash(
    _bb: &Busybox,
    _password: &mut Option<String>,
    _args: &ElkSubcommandArgs,
) -> anyhow::Result<()> {
    todo!()
}

fn setup_auditbeat(
    _bb: &Busybox,
    _password: &mut Option<String>,
    _args: &ElkSubcommandArgs,
) -> anyhow::Result<()> {
    todo!()
}

fn setup_filebeat(
    _bb: &Busybox,
    _password: &mut Option<String>,
    _args: &ElkSubcommandArgs,
) -> anyhow::Result<()> {
    todo!()
}

fn setup_packetbeat(
    _bb: &Busybox,
    _password: &mut Option<String>,
    _args: &ElkSubcommandArgs,
) -> anyhow::Result<()> {
    todo!()
}

fn install_beats(_bb: &Busybox, _distro: Distro, _args: &ElkBeatsArgs) -> anyhow::Result<()> {
    todo!()
}
