//! Utilities for identifying scheduled tasks and persistence

use crate::utils::passwd::load_users;
use crate::utils::qx;
use std::path::Path;

pub struct CronEntry {
    pub user: String,
    pub command: String,
}

pub fn get_active_timers() -> Vec<String> {
    qx("systemctl list-timers --all --no-pager --no-legend")
        .map(|(_, out)| out.lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default()
}

pub fn get_cron_entries() -> eyre::Result<Vec<CronEntry>> {
    let mut entries = Vec::new();
    let mut targets = Vec::new();

    if Path::new("/etc/crontab").exists() {
        targets.push(("root".to_string(), "/etc/crontab".to_string()));
    }

    let users = load_users::<_, &str>(None)?;
    let spool_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron"];

    for dir in spool_dirs {
        for user in &users {
            let p = Path::new(dir).join(&user.user);
            if p.exists() {
                targets.push((user.user.clone(), p.to_string_lossy().to_string()));
            }
        }
    }

    for (user, path) in targets {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
                    continue;
                }
                entries.push(CronEntry {
                    user: user.clone(),
                    command: trimmed.to_string(),
                });
            }
        }
    }
    Ok(entries)
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
                    jobs.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }
    jobs
}
