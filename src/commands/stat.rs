use crate::utils::system;
use clap::{Parser, Subcommand};

/* ============================== CLI ============================== */

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Stat {
    #[command(subcommand)]
    command: Option<StatCommands>,
}

#[derive(Subcommand, Debug)]
pub enum StatCommands {
    /// Raw CPU usage (script-friendly)
    Cpu,
    /// Raw memory usage percent (script-friendly)
    Memory,
    /// Raw disk stats (script-friendly)
    Disk,
    /// Pretty human-readable summary
    Pretty,
}

/* ============================== HELPERS ============================== */

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut size = bytes as f64;
    let mut unit = 0usize;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    format!("{size:.1}{}", UNITS[unit])
}

fn pct(v: f64) -> String {
    format!("{v:.3}%")
}

/* ============================== COMMAND ============================== */

impl super::Command for Stat {
    fn execute(self) -> eyre::Result<()> {
        let cmd = self.command.unwrap_or(StatCommands::Pretty);

        match cmd {
            StatCommands::Cpu => {
                println!("{:.3}", system::cpu_percent()?);
            }
            StatCommands::Memory => {
                println!("{:.3}", system::mem_stats()?.used_percent);
            }
            StatCommands::Disk => {
                let d = system::disk_stats()?;
                println!("{:.1}", d.free_percent);
                println!("{} {}", d.used_bytes, d.total_bytes);
            }
            StatCommands::Pretty => {
                let s = system::snapshot()?;

                println!("┌──────────────────────────┐");
                println!("│        System Stats      │ ");
                println!("├──────────────────────────┘ ");
                println!("│ CPU   {:>17} ", pct(s.cpu_percent));

                println!(
                    "│ MEM   {:>8} {:>8} ",
                    pct(s.mem.used_percent),
                    format!(
                        "{}/{}",
                        fmt_bytes(s.mem.used_bytes),
                        fmt_bytes(s.mem.total_bytes)
                    )
                );

                println!(
                    "│ DISK  {:>8} {:>8} ",
                    format!("{:.1}% free", s.disk.free_percent),
                    format!(
                        "{}/{}",
                        fmt_bytes(s.disk.used_bytes),
                        fmt_bytes(s.disk.total_bytes)
                    )
                );
                println!("└──────────────────────────");
            }
        }

        Ok(())
    }
}
