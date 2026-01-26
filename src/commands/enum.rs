use clap::{Parser, Subcommand};
use std::fmt::Write as _;
use crate::utils::{busybox::Busybox, qx, pager};

/// Perform system enumeration or target specific subsystems
#[derive(Parser, Debug)]
#[command(about = "System enumeration tools")]
pub struct Enum {
    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,
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
                
                pager::page_output(&full_report)
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

        match qx("systemctl is-active sshd || systemctl is-active ssh") {
            Ok((status, res)) if status.success() => writeln!(out, "Service Status: ACTIVE ({})", res.trim())?,
            _ => writeln!(out, "Service Status: INACTIVE or NOT FOUND")?,
        }
        writeln!(out, "---")?;

        for warning in crate::utils::ssh::audit_sshd_config() {
            writeln!(out, "[!] {warning}")?;
        }
        for warning in crate::utils::ssh::audit_ssh_ca() {
            writeln!(out, "[!] {warning}")?;
        }

        let keys = crate::utils::ssh::get_user_keys()?;
        if keys.is_empty() {
            writeln!(out, "No authorized_keys found.")?;
        } else {
            writeln!(out, "{:<12} | {:<30} | PATH", "USER", "COMMENT")?;
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

        writeln!(out, "\n--- Systemd Timers")?;
        let timers = crate::utils::scheduling::get_active_timers();
        if timers.is_empty() {
            writeln!(out, "(none found)")?;
        } else {
            for timer in timers.iter().take(10) {
                writeln!(out, "{timer}")?;
            }
        }

        writeln!(out, "\n--- Active Crontab Commands")?;
        let crons = crate::utils::scheduling::get_cron_entries()?;
        if crons.is_empty() {
            writeln!(out, "(no active cron commands found)")?;
        } else {
            writeln!(out, "{:<12} | COMMAND", "USER")?;
            writeln!(out, "{:-<12}-+-{:-<40}", "", "")?;
            for entry in crons {
                let cmd = if entry.command.len() > 60 {
                    format!("{}...", &entry.command[..57])
                } else {
                    entry.command
                };
                writeln!(out, "{:<12} | {cmd}", entry.user)?;
            }
        }

        // --- Re-integrating At Jobs ---
        writeln!(out, "\n--- At Job Spool Files")?;
        let at_jobs = crate::utils::scheduling::get_at_jobs();
        if at_jobs.is_empty() {
            writeln!(out, "(no at jobs found)")?;
        } else {
            for job in at_jobs {
                writeln!(out, "{job}")?;
            }
        }

        writeln!(out, "\n==== SHELL ANOMALIES & ENVIRONMENT")?;
        for alert in crate::utils::shell_audit::audit_environment_variables() {
            writeln!(out, "[!] {alert}")?;
        }
        
        writeln!(out, "--- Scanning shell configurations (profile, bashrc, xinitrc, etc.)...")?;
        let shell_findings = crate::utils::shell_audit::scan_shell_configs()?;
        if shell_findings.is_empty() {
            writeln!(out, "[-] No suspicious patterns found in global or user shell configs.")?;
        } else {
            for finding in shell_findings {
                writeln!(out, "[!] {} (User: {})", finding.path, finding.user)?;
                for alert in finding.alerts {
                    writeln!(out, "    -> {alert}")?;
                }
            }
        }
        Ok(out)
    }

    fn enum_containers() -> eyre::Result<String> {
        let mut out = String::new();
        writeln!(out, "\n==== CONTAINER RUNTIMES")?;
        let container_info = crate::utils::containers::get_container_summary();
        if container_info.is_empty() {
            writeln!(out, "No active containers or common runtimes (Docker, Podman, LXC, Containerd) detected.")?;
        } else {
            for info in container_info {
                writeln!(out, "{info}")?;
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
