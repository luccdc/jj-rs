//! Utilities for identifying scheduled tasks and persistence

use crate::utils::passwd::load_users;
use crate::utils::qx;
use std::path::Path;
use walkdir::WalkDir;

pub struct CronEntry {
    pub source: String, // e.g., "/etc/crontab" or "user root"
    pub user: String,
    pub command: String,
    pub schedule: String,
}

pub struct SystemdTimer {
    pub unit: String,
    pub next: String,
    pub activestate: String,
}

pub struct PeriodicScript {
    pub path: String,
    pub interval: String, // "daily", "hourly", etc.
}

/// Parses `systemctl list-timers` into structured data
pub fn get_active_timers() -> Vec<SystemdTimer> {
    let mut results = Vec::new();
    // --no-legend removes headers; plain output is easiest to split by whitespace
    if let Ok((status, output)) = qx("systemctl list-timers --all --no-pager --no-legend") 
        && status.success() 
    {
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Systemd list-timers cols usually: NEXT LEFT LAST PASSED UNIT ACTIVESTATE
            if parts.len() >= 6 {
                results.push(SystemdTimer {
                    next: format!("{} {}", parts[0], parts[1]),
                    unit: parts[parts.len() - 2].to_string(),
                    activestate: parts[parts.len() - 1].to_string(),
                });
            }
        }
    }
    results
}

/// Retrieves standard cron lines from /etc/crontab, /etc/cron.d/, and /var/spool/cron/
pub fn get_cron_entries() -> eyre::Result<Vec<CronEntry>> {
    let mut entries = Vec::new();

    // 1. System-wide crontabs (Have USER field)
    let system_paths = vec!["/etc/crontab"];
    let cron_d = "/etc/cron.d";
    
    // Gather all files in /etc/cron.d
    let mut system_files = system_paths.into_iter().map(String::from).collect::<Vec<_>>();
    if Path::new(cron_d).exists() {
        for entry in WalkDir::new(cron_d).max_depth(1).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                system_files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }

    for path in system_files {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
                    continue;
                }
                // System cron format: * * * * * USER COMMAND
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 7 {
                    entries.push(CronEntry {
                        source: path.clone(),
                        schedule: parts[0..5].join(" "),
                        user: parts[5].to_string(),
                        command: parts[6..].join(" "),
                    });
                }
            }
        }
    }

    // 2. User crontabs (NO user field, implied by filename)
    let users = load_users::<_, &str>(None)?;
    let spool_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron"];

    for dir in spool_dirs {
        for user in &users {
            let p = Path::new(dir).join(&user.user);
            // Collapsed check: read_to_string fails safely if file doesn't exist
            if let Ok(content) = std::fs::read_to_string(&p) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
                        continue;
                    }
                    // User cron format: * * * * * COMMAND
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 6 {
                        entries.push(CronEntry {
                            source: p.to_string_lossy().to_string(),
                            schedule: parts[0..5].join(" "),
                            user: user.user.clone(),
                            command: parts[5..].join(" "),
                        });
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Enumerates scripts in /etc/cron.{hourly,daily,weekly,monthly}
pub fn get_periodic_scripts() -> Vec<PeriodicScript> {
    let mut scripts = Vec::new();
    let intervals = ["hourly", "daily", "weekly", "monthly"];

    for interval in intervals {
        let path_str = format!("/etc/cron.{interval}");
        let p = Path::new(&path_str);
        if p.exists() {
            for entry in WalkDir::new(p).min_depth(1).max_depth(1).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    let name = entry.file_name().to_string_lossy();
                    // Ignore typical placeholders like .placeholder or .gitignore
                    if !name.starts_with('.') {
                        scripts.push(PeriodicScript {
                            path: entry.path().to_string_lossy().to_string(),
                            interval: interval.to_string(),
                        });
                    }
                }
            }
        }
    }
    scripts
}

pub fn get_at_jobs() -> Vec<String> {
    let mut jobs = Vec::new();
    let spool_dirs = [
        "/var/spool/cron/atjobs",
        "/var/spool/atjobs",
        "/var/spool/at",
    ];

    for dir in spool_dirs {
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                if entry.path().is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name != ".SEQ" {
                         jobs.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    jobs
}
