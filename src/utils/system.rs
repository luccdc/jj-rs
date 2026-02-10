use eyre::{Result, eyre};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MemStats {
    pub total_bytes: u64,
    pub avail_bytes: u64, // pressure / MemAvailable definition
    pub used_bytes: u64,
    pub used_percent: f64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DiskStats {
    pub total_bytes: u64,
    pub avail_bytes: u64, // available to non-root where possible
    pub used_bytes: u64,
    pub free_percent: f64,
    pub used_percent: f64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Snapshot {
    pub cpu_percent: f64,
    pub mem: MemStats,
    pub disk: DiskStats,
}

/* ============================== CPU ============================== */

#[cfg(unix)]
pub fn cpu_percent() -> Result<f64> {
    fn read_cpu() -> Result<(u64, u64)> {
        let stat = std::fs::read_to_string("/proc/stat")?;
        let line = stat
            .lines()
            .find(|l| l.starts_with("cpu "))
            .ok_or_else(|| eyre!("missing cpu line"))?;

        let mut it = line.split_whitespace();
        it.next(); // "cpu"

        let user: u64 = it.next().ok_or_else(|| eyre!("user"))?.parse()?;
        let nice: u64 = it.next().ok_or_else(|| eyre!("nice"))?.parse()?;
        let system: u64 = it.next().ok_or_else(|| eyre!("system"))?.parse()?;
        let idle: u64 = it.next().ok_or_else(|| eyre!("idle"))?.parse()?;
        let iowait: u64 = it.next().unwrap_or("0").parse()?;
        let irq: u64 = it.next().unwrap_or("0").parse()?;
        let softirq: u64 = it.next().unwrap_or("0").parse()?;
        let steal: u64 = it.next().unwrap_or("0").parse()?;

        let idle_all = idle + iowait;
        let non_idle = user + nice + system + irq + softirq + steal;
        let total = idle_all + non_idle;

        Ok((idle_all, total))
    }

    let mut idle_sum = 0u64;
    let mut total_sum = 0u64;

    // multi-sample for stability
    for _ in 0..5 {
        let (i1, t1) = read_cpu()?;
        std::thread::sleep(std::time::Duration::from_millis(200));
        let (i2, t2) = read_cpu()?;

        idle_sum += i2.saturating_sub(i1);
        total_sum += t2.saturating_sub(t1);
    }

    if total_sum == 0 {
        Ok(0.0)
    } else {
        Ok((1.0 - idle_sum as f64 / total_sum as f64) * 100.0)
    }
}

#[cfg(windows)]
pub fn cpu_percent() -> Result<f64> {
    use windows::Win32::{Foundation::FILETIME, System::Threading::GetSystemTimes};

    unsafe {
        fn merge(f: FILETIME) -> u64 {
            ((f.dwHighDateTime as u64) << 32) | (f.dwLowDateTime as u64)
        }

        let mut idle1 = FILETIME::default();
        let mut kern1 = FILETIME::default();
        let mut user1 = FILETIME::default();

        GetSystemTimes(Some(&mut idle1), Some(&mut kern1), Some(&mut user1))?;

        std::thread::sleep(std::time::Duration::from_millis(1000));

        let mut idle2 = FILETIME::default();
        let mut kern2 = FILETIME::default();
        let mut user2 = FILETIME::default();

        GetSystemTimes(Some(&mut idle2), Some(&mut kern2), Some(&mut user2))?;

        let idle = merge(idle2) - merge(idle1);
        let kern = merge(kern2) - merge(kern1);
        let user = merge(user2) - merge(user1);

        let total = kern + user;
        let busy = total.saturating_sub(idle);

        Ok(100.0 * busy as f64 / total as f64)
    }
}

/* ============================== MEMORY ============================== */

#[cfg(target_os = "linux")]
pub fn mem_stats() -> Result<MemStats> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;

    let mut total_kb = None;
    let mut avail_kb = None;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        } else if line.starts_with("MemAvailable:") {
            avail_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        }

        if total_kb.is_some() && avail_kb.is_some() {
            break;
        }
    }

    let total_kb = total_kb.ok_or_else(|| eyre!("MemTotal missing"))?;
    let avail_kb = avail_kb.ok_or_else(|| eyre!("MemAvailable missing"))?;

    let total = total_kb * 1024;
    let avail = avail_kb * 1024;
    let used = total - avail;

    Ok(MemStats {
        total_bytes: total,
        avail_bytes: avail,
        used_bytes: used,
        used_percent: (used as f64 / total as f64) * 100.0,
    })
}

#[cfg(windows)]
pub fn mem_stats() -> Result<MemStats> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    unsafe {
        let mut m = MEMORYSTATUSEX::default();
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut m)?;

        let total = m.ullTotalPhys;
        let avail = m.ullAvailPhys;
        let used = total - avail;

        Ok(MemStats {
            total_bytes: total,
            avail_bytes: avail,
            used_bytes: used,
            used_percent: m.dwMemoryLoad as f64,
        })
    }
}

/* ============================== DISK ============================== */

#[cfg(unix)]
pub fn disk_stats() -> Result<DiskStats> {
    let vfs = nix::sys::statvfs::statvfs("/")?;

    let block = vfs.block_size() as u64;
    let total = vfs.blocks() * block;
    let avail = vfs.blocks_available() * block;
    let used = total - avail;

    Ok(DiskStats {
        total_bytes: total,
        avail_bytes: avail,
        used_bytes: used,
        free_percent: (avail as f64 / total as f64) * 100.0,
        used_percent: (used as f64 / total as f64) * 100.0,
    })
}

#[cfg(windows)]
pub fn disk_stats() -> Result<DiskStats> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExA;
    use windows_core::s;

    unsafe {
        let mut total = 0u64;
        let mut free = 0u64;

        GetDiskFreeSpaceExA(s!("C:\\"), None, Some(&mut total), Some(&mut free))?;

        let used = total - free;

        Ok(DiskStats {
            total_bytes: total,
            avail_bytes: free,
            used_bytes: used,
            free_percent: (free as f64 / total as f64) * 100.0,
            used_percent: (used as f64 / total as f64) * 100.0,
        })
    }
}

/* ============================== SNAPSHOT ============================== */

pub fn snapshot() -> Result<Snapshot> {
    Ok(Snapshot {
        cpu_percent: cpu_percent()?,
        mem: mem_stats()?,
        disk: disk_stats()?,
    })
}
