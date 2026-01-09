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
            #[cfg(windows)]
            StatCommands::Cpu => unsafe {
                use windows::Win32::{Foundation::FILETIME, System::Threading::GetSystemTimes};

                let mut idle1: FILETIME = std::mem::zeroed();
                let mut kern1: FILETIME = std::mem::zeroed();
                let mut user1: FILETIME = std::mem::zeroed();
                let mut idle2: FILETIME = std::mem::zeroed();
                let mut kern2: FILETIME = std::mem::zeroed();
                let mut user2: FILETIME = std::mem::zeroed();

                GetSystemTimes(
                    Some(&mut idle1 as _),
                    Some(&mut kern1 as _),
                    Some(&mut user1 as _),
                )?;

                std::thread::sleep(std::time::Duration::from_millis(200));

                GetSystemTimes(
                    Some(&mut idle2 as _),
                    Some(&mut kern2 as _),
                    Some(&mut user2 as _),
                )?;

                fn merge_time(f: FILETIME) -> u64 {
                    ((f.dwLowDateTime as u64) << 32) | (f.dwHighDateTime as u64)
                }

                let idle1 = merge_time(idle1);
                let kern1 = merge_time(kern1);
                let user1 = merge_time(user1);
                let idle2 = merge_time(idle2);
                let kern2 = merge_time(kern2);
                let user2 = merge_time(user2);

                let didle = idle2 - idle1;
                let duser = user2 - user1;
                let dkern = kern2 - kern1;

                let dtotal = dkern + duser;
                let dbusy = dtotal - didle;

                let cpu_usage = 100.0 * (dbusy as f32) / (dtotal as f32);

                println!("{cpu_usage:.1}");
            },
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
