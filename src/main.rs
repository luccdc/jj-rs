#![deny(clippy::correctness)]
#![warn(clippy::suspicious)]
#![warn(clippy::pedantic)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::wildcard_imports)]

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod macros;
mod utils;

// Add commands here
//
// Format:
// name, alias => reference::to::Command,
// name => reference::to::Command,
//
// Name should be in camel case
define_commands! {
    commands::Commands {
        // utility commands
        [unix] DownloadShell, ds => download_shell::DownloadShell,
        Check, c => check::Check,
        CheckDaemon, cd => check_daemon::CheckDaemon,
        [unix] Elk => elk::Elk,
        Serve, s => serve::Serve,
        Get, g => get::Get,

        // sysinfo commands
        [unix] Enum, e => r#enum::Enum,
        Ports, p => ports::Ports,
        Stat, st => stat::Stat,

        // admin commands
        Backup, bu => backup::Backup,
        [unix] Useradd, ua => useradd::Useradd,
        [unix] Firewall, fw => firewall::Firewall,
        [unix] Ssh => ssh::Ssh,
        File => file::File,

        // Embedded binaries
        [unix] Nft => nft::Nft,
        [unix] Zsh => zsh::Zsh,
        [unix] Busybox, bb => busybox::Busybox,
    }
}

// Add checks here:
//
// /// Comments describing how to use troubleshooter
// Name, serialized_name => module::Troubleshooter
define_checks! {
    checks::CheckTypes {
        /// Troubleshoot an SSH connection
        Ssh, "ssh" => ssh::SshTroubleshooter,
        Dns, "dns" => dns::Dns,
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: commands::Commands,
}

fn main() -> eyre::Result<()> {
    #[cfg(windows)]
    if let Err(e) = ansi_term::enable_ansi_support() {
        eprintln!("Could not enable ANSI colors");
    }
    let cli = Cli::parse();
    color_eyre::install()?;

    if let Err(e1) = cli.command.setup_tracing()
        && let Err(e2) = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(
                tracing_subscriber::filter::Targets::new()
                    .with_target("jj_rs", tracing::Level::INFO),
            )
            .try_init()
    {
        eprintln!("Could not set up logging! Some messages may be missed");
        eprintln!("{e1}");
        eprintln!("{e2}");
    }
    cli.command.execute()
}
