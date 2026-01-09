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
    /// Print the current CPU statistics based on `/proc/stat`
    #[cfg(unix)]
    Cpu,
    /// Print the current memory statistics
    Memory,
}

impl super::Command for Stat {
    fn execute(self) -> eyre::Result<()> {
        match self.command {
            #[cfg(unix)]
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
            #[cfg(target_os = "linux")]
            StatCommands::Memory => {
                let meminfo = std::fs::read_to_string("/proc/meminfo")?;

                let lines = meminfo.split("\n").collect::<Vec<_>>();

                let total = pcre!(
                    &(lines[0]) =~ m{r"^MemTotal: \s+ ([0-9]+) \s+ kB"}xms
                )[0]
                .extract::<1>()
                .1[0];

                let available = pcre!(
                    &(lines[2]) =~ m{ r"^MemAvailable: \s+ ([0-9]+) \s+ kB" }xms
                )[0]
                .extract::<1>()
                .1[0];

                let total = total.parse::<u32>()? as f32;
                let available = available.parse::<u32>()? as f32;

                println!("{:.1}", (total - available) * 100.0 / total);
            }
            #[cfg(windows)]
            StatCommands::Memory => unsafe {
                use windows::Win32::System::SystemInformation::{
                    GlobalMemoryStatusEx, MEMORYSTATUSEX,
                };

                let mut memory: MEMORYSTATUSEX = std::mem::zeroed();

                memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

                GlobalMemoryStatusEx(&mut memory as _)?;

                println!("{}", memory.dwMemoryLoad);
            },
        }

        Ok(())
    }
}
