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
        #[cfg(target_os = "linux")] DownloadShell, ds => download_shell::DownloadShell,
        Check, c => check::Check,
        #[cfg(target_os = "linux")] CheckDaemon, cd => check_daemon::CheckDaemon,
        #[cfg(target_os = "linux")] Elk => elk::Elk,
        Serve, s => serve::Serve,
        Get, g => get::Get,

        // sysinfo commands
        #[cfg(target_os = "linux")] Enum, e => r#enum::Enum,
        #[cfg(target_os = "linux")] Ports, p => ports::Ports,
        Stat, st => stat::Stat,

        // admin commands
        Backup, bu => backup::Backup,
        #[cfg(target_os = "linux")] Useradd, ua => useradd::Useradd,
        #[cfg(target_os = "linux")] Firewall, fw => firewall::Firewall,
        #[cfg(target_os = "linux")] Ssh => ssh::Ssh,

        // Embedded binaries
        #[cfg(target_os = "linux")] Nft => nft::Nft,
        #[cfg(target_os = "linux")] Jq => jq::Jq,
        #[cfg(target_os = "linux")] Tmux => tmux::Tmux,
        #[cfg(target_os = "linux")] Tcpdump, td => tcpdump::Tcpdump,
        #[cfg(target_os = "linux")] Zsh => zsh::Zsh,
        #[cfg(target_os = "linux")] Busybox, bb => busybox::Busybox,
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
    #[cfg(windows)]
    if let Err(e) = ansi_term::enable_ansi_support() {
        eprintln!("Could not enable ANSI colors");
    }
    let cli = Cli::parse();
    color_eyre::install()?;
    cli.command.execute()
}
