use clap::{Parser, Subcommand};

use crate::utils::system;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Stat {
    #[command(subcommand)]
    command: StatCommands,
}

#[derive(Subcommand, Debug)]
pub enum StatCommands {
    Cpu,
    Memory,
    Disk,
}

fn print_pct(value: f64) {
    println!("{value:.1}%");
}

impl super::Command for Stat {
    fn execute(self) -> eyre::Result<()> {
        match self.command {
            StatCommands::Cpu => {
                // Keep your current “more accurate” averaging behavior
                let pct = system::cpu_usage_percent(system::CpuMode::Average { samples: 5 }, 200)?;
                print_pct(pct);
            }
            StatCommands::Memory => {
                let mem = system::mem_stats()?;
                print_pct(mem.used_percent);
            }
            StatCommands::Disk => {
                let disk = system::disk_root_stats()?;
                println!("free: {:.1}%", disk.free_percent);
                println!(
                    "used: {} / {}",
                    system::fmt_bytes(disk.used_bytes),
                    system::fmt_bytes(disk.total_bytes)
                );
            }
        }

        Ok(())
    }
}
