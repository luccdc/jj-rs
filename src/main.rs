use clap::Parser;

mod checks;
mod commands;
mod macros;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

define_commands! {
    Backup => commands::backup::Backup,
    Busybox => commands::busybox::Busybox,
    DownloadShell => commands::download_shell::DownloadShell
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    cli.command.execute()
}
