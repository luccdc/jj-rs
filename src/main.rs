#![deny(clippy::correctness)]
#![warn(clippy::suspicious)]
#![warn(clippy::pedantic)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::wildcard_imports)]

use clap::Parser;

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
        [unix] CheckDaemon, cd => check_daemon::CheckDaemon,
        [unix] Elk => elk::Elk,
        Serve, s => serve::Serve,

        // sysinfo commands
        [unix] Enum, e => r#enum::Enum,
        [unix] Ports, p => ports::Ports,
        Stat, st => stat::Stat,

        // admin commands
        Backup, bu => backup::Backup,
        [unix] Useradd, ua => useradd::Useradd,
        [unix] Firewall, fw => firewall::Firewall,
        [unix] Ssh => ssh::Ssh,

        // Embedded binaries
        [unix] Nft => nft::Nft,
        [unix] Jq => jq::Jq,
        [unix] Tmux => tmux::Tmux,
        [unix] Tcpdump, td => tcpdump::Tcpdump,
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
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: commands::Commands,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    color_eyre::install()?;
    cli.command.execute()
}
