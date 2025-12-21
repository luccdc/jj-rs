#![deny(clippy::correctness)]
#![warn(clippy::suspicious)]
#![warn(clippy::pedantic)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::wildcard_imports)]

use clap::Parser;

mod checks;
mod commands;
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
    Commands {
        // utility commands
        [unix] DownloadShell, ds => commands::download_shell::DownloadShell,
        Check, c => commands::check::Check,
        [unix] CheckDaemon, cd => commands::check_daemon::CheckDaemon,
        [unix] Elk => commands::elk::Elk,
        Serve, s => commands::serve::Serve,

        // sysinfo commands
        [unix] Enum, e => commands::r#enum::Enum,
        [unix] Ports, p => commands::ports::Ports,
        [unix] Stat => commands::stat::Stat,

        // admin commands
        Backup, bu => commands::backup::Backup,
        [unix] Useradd, ua => commands::useradd::Useradd,
        [unix] Firewall, fw => commands::firewall::Firewall,
        [unix] Ssh => commands::ssh::Ssh,

        // Embedded binaries
        [unix] Nft => commands::nft::Nft,
        [unix] Jq => commands::jq::Jq,
        [unix] Tmux => commands::tmux::Tmux,
        [unix] Tcpdump, td => commands::tcpdump::Tcpdump,
        [unix] Zsh => commands::zsh::Zsh,
        [unix] Busybox, bb => commands::busybox::Busybox,
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    color_eyre::install()?;
    cli.command.execute()
}
