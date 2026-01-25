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
                .map_or_else(|_| "(unable to query cpu info)".to_string(), |(_, lscpu)| lscpu)
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
            println!("{:<12} | {:<30} | PATH", "USER", "COMMENT");
            println!("{:-<12}-+-{:-<30}-+-{:-<30}", "", "", "");
            for key in keys {
                println!("{:<12} | {:<30} | {}", key.user, key.comment, key.path);
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
        let at_jobs = crate::utils::scheduling::get_at_jobs();
        if at_jobs.is_empty() {
            println!("(no at jobs found)");
        } else {
            for job in at_jobs {
                println!("{job}");
            }
        }

        // Container Runtime Audit
        println!("\n==== CONTAINER RUNTIMES\n");
        let container_info = crate::utils::containers::get_container_summary();
        if container_info.is_empty() {
            println!("No active containers or common runtimes (Docker, Podman, LXC) detected.");
        } else {
            for info in container_info {
                println!("{info}");
            }
        }

        // Shell & Environment Audit
        println!("\n==== SHELL ANOMALIES & ENVIRONMENT\n");
        let env_alerts = crate::utils::shell_audit::audit_environment_variables();
        if env_alerts.is_empty() {
            println!("[-] No high-risk environment variables (LD_PRELOAD, etc.) detected.");
        } else {
            for alert in env_alerts {
                println!("{alert}");
            }
        }

        println!("--- Scanning shell configurations for persistence and shadowing...");
        let shell_findings = crate::utils::shell_audit::scan_shell_configs()?;
        if shell_findings.is_empty() {
            println!("[-] No suspicious patterns found in global or user shell configs.");
        } else {
            for finding in shell_findings {
                println!("[!] {} (User: {})", finding.path, finding.user);
                for alert in finding.alerts {
                    println!("    -> {alert}");
                }
            }
        }

        println!("\n==== PORTS INFO\n");
        super::ports::Ports.execute()?;

        Ok(())
    }
}
