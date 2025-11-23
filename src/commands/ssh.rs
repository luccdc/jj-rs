use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Ssh {
    #[command(subcommand)]
    command: SshCommands,
}

#[derive(Subcommand, Debug)]
pub enum SshCommands {
    /// Perform a service check against an SSH daemon
    Check(crate::checks::ssh::SshTroubleshooter),
}

impl super::Command for Ssh {
    fn execute(self) -> anyhow::Result<()> {
        match self.command {
            SshCommands::Check(ssh_troubleshooter) => {
                let mut t = crate::utils::checks::CliTroubleshooter::new(false, false, false);

                t.run_cli(&ssh_troubleshooter)?;
                Ok(())
            }
        }
    }
}
