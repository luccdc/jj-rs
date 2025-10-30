use clap::{Parser, Subcommand};

use crate::pcre;

/// Print current system statistics
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Stat {
    #[command(subcommand)]
    command: StatCommands,
}

#[derive(Subcommand, Debug)]
pub enum StatCommands {
    Cpu,
}

impl super::Command for Stat {
    fn execute(self) -> anyhow::Result<()> {
        match self.command {
            StatCommands::Cpu => {
                let stat = std::fs::read_to_string("/proc/stat")?;

                let [user, system, idle] = pcre!(
                    &stat =~ m{
                        r"^cpu \s+ ([0-9]+) \s+ [0-9]+ \s+ ([0-9]+) \s+ ([0-9]+) \s+ .*$"
                    }xms
                )[0]
                .extract::<3>()
                .1;

                let user: f64 = user.parse()?;
                let system: f64 = system.parse()?;
                let idle: f64 = idle.parse()?;

                let usage = (user + system) * 100.0 / (user + system + idle);

                println!("{usage:.5}%");
            }
        }

        Ok(())
    }
}
