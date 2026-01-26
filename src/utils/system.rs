#![allow(dead_code)]
//metrics like cpumode::instant are never used and memstats data are never read
//so they can be used for future commands
use eyre::eyre;

/// How CPU usage should be sampled.
#[derive(Debug, Clone, Copy)]
pub enum CpuMode {
    /// One delta sample over `interval_ms`.
    Instant,
    /// Average of N delta samples, each separated by `interval_ms`.
    Average { samples: u32 },
}

#[derive(Debug, Clone, Copy)]
pub struct MemStats {
    pub total_bytes: u64,
    pub avail_bytes: u64, // "available" / pressure definition
    pub used_bytes: u64,
    pub used_percent: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct DiskStats {
    pub total_bytes: u64,
    pub avail_bytes: u64, // available to caller/non-root where possible
    pub used_bytes: u64,
    pub free_percent: f64,
    pub used_percent: f64,
}

/// Human-readable formatter you can reuse anywhere.
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut size = bytes as f64;
    let mut unit = 0usize;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    format!("{size:.1}{}", UNITS[unit])
}

/// CPU usage as a percent [0..100].
pub fn cpu_usage_percent(mode: CpuMode, interval_ms: u64) -> eyre::Result<f64> {
    #[cfg(unix)]
    {
        fn read_cpu_times() -> eyre::Result<(u64, u64)> {
            let stat = std::fs::read_to_string("/proc/stat")?;
            let line = stat
                .lines()
                .find(|l| l.starts_with("cpu "))
                .ok_or_else(|| eyre!("missing cpu line in /proc/stat"))?;

            // cpu user nice system idle iowait irq softirq steal guest guest_nice
            let mut it = line.split_whitespace();
            let _ = it.next(); // "cpu"

            let user: u64 = it.next().ok_or_else(|| eyre!("cpu user"))?.parse()?;
            let nice: u64 = it.next().ok_or_else(|| eyre!("cpu nice"))?.parse()?;
            let system: u64 = it.next().ok_or_else(|| eyre!("cpu system"))?.parse()?;
            let idle: u64 = it.next().ok_or_else(|| eyre!("cpu idle"))?.parse()?;
            let iowait: u64 = it.next().unwrap_or("0").parse()?;
            let irq: u64 = it.next().unwrap_or("0").parse()?;
            let softirq: u64 = it.next().unwrap_or("0").parse()?;
            let steal: u64 = it.next().unwrap_or("0").parse()?;

            let idle_all = idle + iowait;
            let non_idle = user + nice + system + irq + softirq + steal;
            let total = idle_all + non_idle;

            Ok((idle_all, total))
        }

        let samples = match mode {
            CpuMode::Instant => 1,
            CpuMode::Average { samples } => samples.max(1),
        };

        let mut idle_sum = 0u64;
        let mut total_sum = 0u64;

        for _ in 0..samples {
            let (idle1, total1) = read_cpu_times()?;
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            let (idle2, total2) = read_cpu_times()?;

            idle_sum += idle2.saturating_sub(idle1);
            total_sum += total2.saturating_sub(total1);
        }

        let percent = if total_sum == 0 {
            0.0
        } else {
            (1.0 - (idle_sum as f64 / total_sum as f64)) * 100.0
        };

        return Ok(percent);
    }

    #[cfg(windows)]
    unsafe {
        use windows::Win32::{Foundation::FILETIME, System::Threading::GetSystemTimes};

        fn merge_time(f: FILETIME) -> u64 {
            ((f.dwHighDateTime as u64) << 32) | (f.dwLowDateTime as u64)
        }

        let samples = match mode {
            CpuMode::Instant => 1,
            CpuMode::Average { samples } => samples.max(1),
        };

        let mut didle_sum = 0u64;
        let mut dtotal_sum = 0u64;

        for _ in 0..samples {
            let mut idle1: FILETIME = std::mem::zeroed();
            let mut kern1: FILETIME = std::mem::zeroed();
            let mut user1: FILETIME = std::mem::zeroed();
            let mut idle2: FILETIME = std::mem::zeroed();
            let mut kern2: FILETIME = std::mem::zeroed();
            let mut user2: FILETIME = std::mem::zeroed();

            GetSystemTimes(Some(&mut idle1), Some(&mut kern1), Some(&mut user1))?;
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            GetSystemTimes(Some(&mut idle2), Some(&mut kern2), Some(&mut user2))?;

            let idle1 = merge_time(idle1);
            let kern1 = merge_time(kern1);
            let user1 = merge_time(user1);
            let idle2 = merge_time(idle2);
            let kern2 = merge_time(kern2);
            let user2 = merge_time(user2);

            let didle = idle2.saturating_sub(idle1);
            let dkern = kern2.saturating_sub(kern1);
            let duser = user2.saturating_sub(user1);

            let dtotal = dkern + duser;

            didle_sum += didle;
            dtotal_sum += dtotal;
        }

        let percent = if dtotal_sum == 0 {
            0.0
        } else {
            let dbusy = dtotal_sum.saturating_sub(didle_sum);
            100.0 * (dbusy as f64) / (dtotal_sum as f64)
        };

        return Ok(percent);
    }
}

/// Memory stats showing the memory avaliable.
pub fn mem_stats() -> eyre::Result<MemStats> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;

        let mut total_kb: Option<u64> = None;
        let mut avail_kb: Option<u64> = None;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total_kb = line.split_whitespace().nth(1).and_then(|n| n.parse().ok());
            } else if line.starts_with("MemAvailable:") {
                avail_kb = line.split_whitespace().nth(1).and_then(|n| n.parse().ok());
            }

            if total_kb.is_some() && avail_kb.is_some() {
                break;
            }
        }

        let total_bytes = total_kb.ok_or_else(|| eyre!("MemTotal not found"))? * 1024;
        let avail_bytes = avail_kb.ok_or_else(|| eyre!("MemAvailable not found"))? * 1024;
        let used_bytes = total_bytes.saturating_sub(avail_bytes);

        let used_percent = if total_bytes == 0 {
            0.0
        } else {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        };

        return Ok(MemStats {
            total_bytes,
            avail_bytes,
            used_bytes,
            used_percent,
        });
    }

    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        let mut memory: MEMORYSTATUSEX = std::mem::zeroed();
        memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut memory as _)?;

        let total_bytes = memory.ullTotalPhys;
        let avail_bytes = memory.ullAvailPhys;
        let used_bytes = total_bytes.saturating_sub(avail_bytes);

        let used_percent = if total_bytes == 0 {
            0.0
        } else {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        };

        return Ok(MemStats {
            total_bytes,
            avail_bytes,
            used_bytes,
            used_percent,
        });
    }
}

/// Disk stats for the main drive: "/" on Unix, "C:\" on Windows.
pub fn disk_root_stats() -> eyre::Result<DiskStats> {
    #[cfg(unix)]
    {
        let vfs = nix::sys::statvfs::statvfs("/")?;
        let block_size = vfs.block_size() as u64;

        let total_bytes = (vfs.blocks() as u64).saturating_mul(block_size);
        let avail_bytes = (vfs.blocks_available() as u64).saturating_mul(block_size);
        let used_bytes = total_bytes.saturating_sub(avail_bytes);

        let free_percent = if total_bytes == 0 {
            0.0
        } else {
            (avail_bytes as f64 / total_bytes as f64) * 100.0
        };

        let used_percent = if total_bytes == 0 {
            0.0
        } else {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        };

        return Ok(DiskStats {
            total_bytes,
            avail_bytes,
            used_bytes,
            free_percent,
            used_percent,
        });
    }

    #[cfg(windows)]
    unsafe {
        use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExA;

        let mut total: u64 = 0;
        let mut free: u64 = 0;

        GetDiskFreeSpaceExA(
            windows_core::s!(r"C:\"),
            Some(&mut free as _),  // free bytes available to caller
            Some(&mut total as _), // total bytes
            None,
        )?;

        let total_bytes = total;
        let avail_bytes = free;
        let used_bytes = total_bytes.saturating_sub(avail_bytes);

        let free_percent = if total_bytes == 0 {
            0.0
        } else {
            (avail_bytes as f64 / total_bytes as f64) * 100.0
        };

        let used_percent = if total_bytes == 0 {
            0.0
        } else {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        };

        return Ok(DiskStats {
            total_bytes,
            avail_bytes,
            used_bytes,
            free_percent,
            used_percent,
        });
    }
}
