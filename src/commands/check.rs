use clap::{Parser, Subcommand};

use crate::checks::{self, TroubleshooterRunner};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Check {
    #[arg(short = 's', long)]
    show_successful_steps: bool,

    #[arg(short = 'n', long)]
    show_not_run_steps: bool,

    #[command(subcommand)]
    check_type: CheckCommands,
}

#[derive(Subcommand, Debug)]
pub enum CheckCommands {
    Ssh(checks::ssh::SshTroubleshooter),
}

impl super::Command for Check {
    fn execute(self) -> anyhow::Result<()> {
        let mut t = TroubleshooterRunner::new(self.show_successful_steps, self.show_not_run_steps);

        match self.check_type {
            CheckCommands::Ssh(ssh) => t.run_cli(ssh),
        }?;

        Ok(())
    }
}
