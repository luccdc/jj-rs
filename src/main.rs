#![feature(unwrap_infallible)]
#![feature(never_type)]

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
    // utility commands
    DownloadShell, ds => commands::download_shell::DownloadShell,
    Check, c => commands::check::Check,
    Elk => commands::elk::Elk,
    Serve, s => commands::serve::Serve,

    // sysinfo commands
    Enum, e => commands::r#enum::Enum,
    Ports, p => commands::ports::Ports,
    Stat => commands::stat::Stat,

    // admin commands
    Backup, bu => commands::backup::Backup,
    Useradd, ua => commands::useradd::Useradd,
    Firewall, fw => commands::firewall::Firewall,
    Ssh => commands::ssh::Ssh,

    // Embedded binaries
    Nft => commands::nft::Nft,
    Jq => commands::jq::Jq,
    Tmux => commands::tmux::Tmux,
    Tcpdump, td => commands::tcpdump::Tcpdump,
    Zsh => commands::zsh::Zsh,
    Busybox, bb => commands::busybox::Busybox,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    cli.command.execute()
}
