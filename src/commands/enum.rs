use clap::Parser;

use crate::utils::{busybox::Busybox, qx};

/// Perform basic enumeration of the system
#[derive(Parser, Debug)]
pub struct Enum;

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let bb = Busybox::new()?;

        println!("\n==== CPU INFO\n");
        println!(
            "{}",
            qx(r"lscpu | grep -E '^(Core|Thread|CPU)\(s\)'")
                .map(|(_, lscpu)| lscpu)
                .unwrap_or_else(|_| "(unable to query cpu info)".to_string())
        );

        println!("\n==== MEMORY/STORAGE INFO\n");
        bb.command("free").arg("-h").spawn()?.wait()?;
        println!("---");
        bb.command("df").arg("-h").spawn()?.wait()?;

        println!("\n==== SSH AUDIT\n");
        for warning in crate::utils::ssh::audit_sshd_config() {
            println!("[!] {warning}");
        }
        let keys = crate::utils::ssh::get_user_keys()?;
        if keys.is_empty() {
            println!("No authorized_keys found.");
        } else {
            println!("{:<12} | {:<20} | PATH", "USER", "COMMENT");
            println!("{:-<12}-+-{:-<20}-+-{:-<30}", "", "", "");
            for key in keys {
                println!("{:<12} | {:<20} | {}", key.user, key.comment, key.path);
            }
        }

        println!("\n==== SCHEDULED TASKS\n");
        println!("--- Systemd Timers");
        let timers = crate::utils::scheduling::get_active_timers();
        if timers.is_empty() {
            println!("(none found)");
        } else {
            for timer in timers.iter().take(10) {
                println!("{timer}");
            }
        }

        println!("\n--- Active Crontab Commands");
        let crons = crate::utils::scheduling::get_cron_entries()?;
        if crons.is_empty() {
            println!("(no active cron commands found)");
        } else {
            println!("{:<12} | COMMAND", "USER");
            println!("{:-<12}-+-{:-<40}", "", "");
            for entry in crons {
                let cmd = if entry.command.len() > 60 {
                    format!("{}...", &entry.command[..57])
                } else {
                    entry.command
                };
                println!("{:<12} | {cmd}", entry.user);
            }
        }

        println!("\n--- At Job Spool Files");
        let at_jobs = crate::utils::scheduling::get_at_jobs()?;
        if at_jobs.is_empty() {
            println!("(no at jobs found)");
        } else {
            for job in at_jobs {
                println!("{job}");
            }
        }

        println!("\n==== PORTS INFO\n");
        super::ports::Ports.execute()?;

        Ok(())
    }
}
