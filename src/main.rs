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
    Backup, bu => commands::backup::Backup,
    Busybox, bb => commands::busybox::Busybox,
    Enum, e => commands::r#enum::Enum,
    Ports, p => commands::ports::Ports,
    DownloadShell, ds => commands::download_shell::DownloadShell,
    Stat => commands::stat::Stat
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
