use clap::Parser;

mod checks;
mod commands;
mod macros;
mod utils;

use macros::*;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

define_commands! {
    Backup => commands::backup::Backup,
    B => commands::backup::Backup,
}

fn main() -> Result<(), std::process::ExitCode> {
    let cli = Cli::parse();
    cli.command.execute()
}
