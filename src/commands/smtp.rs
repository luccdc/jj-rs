use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::checks::smtp;
use crate::utils::checks::{CheckResultType, check_fn};
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Smtp {
    #[command(subcommand)]
    command: SmtpCommands,
}

#[derive(Subcommand, Debug)]
pub enum SmtpCommands {
    /// Perform a service check against an SSH daemon
    Check(smtp::SmtpTroubleshooter),
    Login(smtp::SmtpTroubleshooter),
}

impl super::Command for Smtp {
    fn execute(self) -> eyre::Result<()> {
        match self.command {
            SmtpCommands::Check(smtp_troubleshooter) => {
                let mut t = crate::utils::checks::CliTroubleshooter::new(false, false, false);

                t.run_cli(&smtp_troubleshooter)?;
                Ok(())
            }

            SmtpCommands::Login(smtp_troubleshooter) => {
                let mut t = crate::utils::checks::CliTroubleshooter::new(false, false, false);
                let start = t.run_checks(&vec![check_fn("Try remote login", |tr| {
                    smtp_troubleshooter.try_remote_login(tr)
                })])?;

                match start {
                    CheckResultType::Failure => {
                        println!("{}", "Unable to log in".red());
                    }
                    CheckResultType::NotRun => {
                        println!("{}", "Login did not run".cyan());
                    }
                    CheckResultType::Success => {
                        println!("{}", "Login successful!".green());
                    }
                }

                Ok(())
            }
        }
    }
}
