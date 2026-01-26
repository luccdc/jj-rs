use clap::{Parser, Subcommand};
use std::fmt::Write as _;
use crate::utils::{busybox::Busybox, qx, pager};

/// Perform system enumeration or target specific subsystems
#[derive(Parser, Debug)]
#[command(about = "System enumeration tools")]
pub struct Enum {
    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,

    /// Disable the output pager
    #[arg(long)]
    pub no_pager: bool,
}

#[derive(Subcommand, Debug)]
pub enum EnumSubcommands {
    /// Hardware specifications (CPU, Memory, Storage)
    Hardware,
    /// Persistence and execution hooks (Cron, Timers, Shell configs)
    Autoruns,
    /// Container runtimes and compose files (Docker, Podman, LXC, Containerd)
    Containers,
    /// Current network ports and listening services
    Ports {
        #[arg(long, short = 'c')]
        display_cmdline: bool,
    },
    /// SSH daemon audit and authorized keys
    Ssh,
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        match self.subcommand {
            Some(EnumSubcommands::Hardware) => {
                print!("{}", Self::enum_hardware()?);
                Ok(())
            }
            Some(EnumSubcommands::Ssh) => {
                print!("{}", Self::enum_ssh()?);
                Ok(())
            }
            Some(EnumSubcommands::Autoruns) => {
                print!("{}", Self::enum_autoruns()?);
                Ok(())
            }
            Some(EnumSubcommands::Containers) => {
                print!("{}", Self::enum_containers()?);
                Ok(())
            }
            Some(EnumSubcommands::Ports { display_cmdline }) => {
                print!("{}", Self::enum_ports(display_cmdline)?);
                Ok(())
            }
            None => {
                let mut full_report = String::new();
                full_report.push_str(&Self::enum_hardware()?);
                full_report.push_str(&Self::enum_ssh()?);
                full_report.push_str(&Self::enum_autoruns()?);
                full_report.push_str(&Self::enum_containers()?);
                full_report.push_str(&Self::enum_ports(false)?);
                
                if self.no_pager {
                    print!("{full_report}");
                    Ok(())
                } else {
                    pager::page_output(&full_report)
                }
            }
        }
    }
}

impl Enum {
    fn enum_hardware() -> eyre::Result<String> {
        let mut out = String::new();
        let bb = Busybox::new()?;
        writeln!(out, "\n==== HARDWARE INFO")?;
        
        let cpu = qx(r"lscpu | grep -E '^(Core|Thread|CPU)\(s\)'")
            .map_or_else(|_| "(unable to query cpu info)".to_string(), |(_, lscpu)| lscpu);
        writeln!(out, "\nCPU:\n{cpu}")?;

        writeln!(out, "\nMEMORY:")?;
        let res = bb.command("free").arg("-h").output()?;
        out.push_str(&String::from_utf8_lossy(&res.stdout));

        writeln!(out, "\nSTORAGE:")?;
        let res = bb.command("df").arg("-h").output()?;
        out.push_str(&String::from_utf8_lossy(&res.stdout));
        
        Ok(out)
    }

    fn enum_ssh() -> eyre::Result<String> {
        let mut out = String::new();
        writeln!(out, "\n==== SSH AUDIT")?;

        // Check service status
        match qx("systemctl is-active sshd || systemctl is-active ssh") {
            Ok((status, res)) if status.success() => writeln!(out, "Service Status: ACTIVE ({})", res.trim())?,
            _ => writeln!(out, "Service Status: INACTIVE or NOT FOUND")?,
        }
        writeln!(out, "---")?;

        // Config Issues
        let config_issues = crate::utils::ssh::audit_sshd_config();
        if config_issues.is_empty() {
             writeln!(out, "[-] No risky sshd_config settings found.")?;
        } else {
             for issue in config_issues {
                 writeln!(out, "[!] Risky Setting: {} = {} (Raw: {})", issue.setting, issue.value, issue.raw_line)?;
             }
        }

        // CA/Principal Issues
        let ca_issues = crate::utils::ssh::audit_ssh_ca();
        for issue in ca_issues {
            writeln!(out, "[!] CA/Principal Feature Detected: {} (Raw: {})", issue.key, issue.raw_line)?;
        }

        // Keys
        let keys = crate::utils::ssh::get_user_keys()?;
        if keys.is_empty() {
            writeln!(out, "\nNo authorized_keys found.")?;
        } else {
            writeln!(out, "\n{:<12} | {:<30} | PATH", "USER", "COMMENT")?;
            writeln!(out, "{:-<12}-+-{:-<30}-+-{:-<30}", "", "", "")?;
            for key in keys {
                writeln!(out, "{:<12} | {:<30} | {}", key.user, key.comment, key.path)?;
            }
        }
        Ok(out)
    }

    fn enum_autoruns() -> eyre::Result<String> {
        let mut out = String::new();
        writeln!(out, "\n==== SCHEDULED TASKS & PERSISTENCE")?;

        // --- Systemd Timers ---
        writeln!(out, "\n--- Systemd Timers")?;
        let timers = crate::utils::scheduling::get_active_timers();
        if timers.is_empty() {
            writeln!(out, "(none found)")?;
        } else {
            writeln!(out, "{:<30} | {:<40} | STATUS", "NEXT RUN", "UNIT")?;
            for timer in timers.iter().take(15) {
                writeln!(out, "{:<30} | {:<40} | {}", timer.next, timer.unit, timer.activestate)?;
            }
        }

        // --- Cron Entries ---
        writeln!(out, "\n--- Active Crontab Commands")?;
        let crons = crate::utils::scheduling::get_cron_entries()?;
        if crons.is_empty() {
            writeln!(out, "(no active cron commands found)")?;
        } else {
            writeln!(out, "{:<12} | {:<15} | COMMAND (Source)", "USER", "SCHEDULE")?;
            writeln!(out, "{:-<12}-+-{:-<15}-+-{:-<40}", "", "", "")?;
            for entry in crons {
                let cmd_display = if entry.command.len() > 50 {
                    format!("{}...", &entry.command[..47])
                } else {
                    entry.command.clone()
                };
                writeln!(out, "{:<12} | {:<15} | {} ({})", entry.user, entry.schedule, cmd_display, entry.source)?;
            }
        }

        // --- Periodic Scripts ---
        let periodic = crate::utils::scheduling::get_periodic_scripts();
        if !periodic.is_empty() {
            writeln!(out, "\n--- Periodic Scripts (cron.daily/hourly/etc)")?;
            for script in periodic {
                writeln!(out, "[{}] {}", script.interval, script.path)?;
            }
        }

        // --- At Jobs ---
        writeln!(out, "\n--- At Job Spool Files")?;
        let at_jobs = crate::utils::scheduling::get_at_jobs();
        if at_jobs.is_empty() {
            writeln!(out, "(no at jobs found)")?;
        } else {
            for job in at_jobs {
                writeln!(out, "{job}")?;
            }
        }

        // --- Shell Audit ---
        writeln!(out, "\n==== SHELL ANOMALIES & ENVIRONMENT")?;
        
        let env_issues = crate::utils::shell_audit::audit_environment_variables();
        for issue in env_issues {
            writeln!(out, "[!] {} ({:?}) -> {}", issue.description, issue.issue_type, issue.raw_content)?;
        }
        
        writeln!(out, "\n--- Scanning shell configurations...")?;
        let shell_findings = crate::utils::shell_audit::scan_shell_configs()?;
        if shell_findings.is_empty() {
            writeln!(out, "[-] No suspicious patterns found in shell configs.")?;
        } else {
            for finding in shell_findings {
                writeln!(out, "User: {} | File: {}", finding.user, finding.path)?;
                for issue in finding.issues {
                    let prefix = match issue.issue_type {
                        crate::utils::shell_audit::ShellIssueType::SuspiciousEnvVar => "[VAR]",
                        crate::utils::shell_audit::ShellIssueType::SensitiveKeyword => "[KEY]",
                        crate::utils::shell_audit::ShellIssueType::AliasShadowing => "[ALIAS]",
                    };
                    writeln!(out, "    {} {} (Line: {:?})", prefix, issue.description, issue.line_number.unwrap_or(0))?;
                }
            }
        }
        Ok(out)
    }

    fn enum_containers() -> eyre::Result<String> {
        let mut out = String::new();
        writeln!(out, "\n==== CONTAINER RUNTIMES")?;
        
        let containers = crate::utils::containers::get_containers();
        
        if containers.is_empty() {
            writeln!(out, "No active containers detected.")?;
        } else {
            writeln!(out, "{:<28} | {:<15} | {:<20} | {:<25} | IMAGE", "RUNTIME", "ID", "STATUS", "NAME")?;
            writeln!(out, "{:-<28}-+-{:-<15}-+-{:-<20}-+-{:-<25}-+-{:-<20}", "", "", "", "", "")?;
            
            for c in containers {
                let runtime_display = if let Some(ns) = &c.namespace {
                    format!("{} ({})", c.runtime, ns)
                } else {
                    c.runtime.clone()
                };
                
                let name_display = if c.name.len() > 24 {
                    format!("{}...", &c.name[..21])
                } else {
                    c.name.clone()
                };

                let id_display = if c.id.len() > 12 {
                    &c.id[..12]
                } else {
                    &c.id
                };

                writeln!(out, "{:<28} | {:<15} | {:<20} | {:<25} | {}", 
                    runtime_display, 
                    id_display, 
                    c.status, 
                    name_display,
                    c.image
                )?;
            }
        }
        
        let compose = crate::utils::containers::find_compose_files();
        if !compose.is_empty() {
            writeln!(out, "\n--- Discovered Docker Compose Files")?;
            for path in compose {
                writeln!(out, "[+] {path}")?;
            }
        }
        Ok(out)
    }

    fn enum_ports(display_cmdline: bool) -> eyre::Result<String> {
        let mut out = String::new();
        writeln!(out, "\n==== PORTS INFO")?;
        let p = super::ports::Ports { display_cmdline };
        out.push_str(&p.get_output()?);
        Ok(out)
    }
}
