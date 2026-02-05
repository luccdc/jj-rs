use std::io::Write;

use clap::{Parser, Subcommand};

use crate::utils::{
    busybox::Busybox,
    logs::{ellipsize, truncate},
    pager, qx,
};

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
    #[command(visible_alias("h"))]
    Hardware,

    /// Persistence and execution hooks (Cron, Timers, Shell configs)
    #[command(visible_alias("a"))]
    Autoruns,

    /// Container runtimes and compose files (Docker, Podman, LXC, Containerd)
    #[command(visible_alias("c"))]
    Containers,

    /// Current network ports and listening services
    #[command(visible_alias("p"))]
    Ports(super::ports::Ports),

    /// SSH daemon audit and authorized keys
    #[command(visible_alias("s"))]
    Ssh,
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(self.no_pager);

        match self.subcommand {
            Some(EnumSubcommands::Hardware) => enum_hardware(&mut ob),
            Some(EnumSubcommands::Ssh) => enum_ssh(&mut ob),
            Some(EnumSubcommands::Autoruns) => enum_autoruns(&mut ob),
            Some(EnumSubcommands::Containers) => enum_containers(&mut ob),
            Some(EnumSubcommands::Ports(ports)) => enum_ports(&mut ob, ports),
            None => {
                enum_hardware(&mut ob)?;
                enum_ssh(&mut ob)?;
                enum_autoruns(&mut ob)?;
                enum_containers(&mut ob)?;
                enum_ports(
                    &mut ob,
                    super::ports::Ports::default_with_pager(self.no_pager),
                )?;

                Ok(())
            }
        }
    }
}

fn enum_hardware(out: &mut impl Write) -> eyre::Result<()> {
    let bb = Busybox::new()?;
    writeln!(out, "\n==== HARDWARE INFO")?;

    let cpu = qx(r"lscpu | grep -E '^(Core|Thread|CPU)\(s\)'").map_or_else(
        |_| "(unable to query cpu info)".to_string(),
        |(_, lscpu)| lscpu,
    );
    writeln!(out, "\nCPU:\n{cpu}")?;

    writeln!(out, "\nMEMORY:")?;
    let res = bb.command("free").arg("-h").output()?;
    writeln!(out, "{}", String::from_utf8_lossy(&res.stdout))?;

    writeln!(out, "\nSTORAGE:")?;
    let res = bb.command("df").arg("-h").output()?;
    writeln!(out, "{}", String::from_utf8_lossy(&res.stdout))?;

    Ok(())
}

fn enum_ssh(out: &mut impl Write) -> eyre::Result<()> {
    writeln!(out, "\n==== SSH AUDIT")?;

    // 1. Config Issues
    let config_issues = crate::utils::ssh::audit_sshd_config();
    for issue in config_issues {
        writeln!(
            out,
            "! {} {} ({})",
            issue.setting, issue.value, issue.filename
        )?;
    }

    // 2. CA/Principal Issues
    let ca_issues = crate::utils::ssh::audit_ssh_ca();
    for issue in ca_issues {
        writeln!(out, "! {} ({})", issue.raw_line, issue.filename)?;
    }

    // 3. Keys
    let keys = crate::utils::ssh::get_user_keys()?;
    if keys.is_empty() {
        writeln!(out, "\n(No authorized_keys found)")?;
    } else {
        for key in keys {
            // Show suffix (last 15 chars) per feedback
            let suffix = if key.key.len() > 15 {
                &key.key[key.key.len() - 15..]
            } else {
                &key.key
            };

            writeln!(
                out,
                "+ Key: {} ...{} (User: {} | {}) -> {}",
                key.key_type, suffix, key.user, key.comment, key.path
            )?;
        }
    }
    Ok(())
}

fn enum_autoruns(out: &mut impl Write) -> eyre::Result<()> {
    writeln!(out, "\n==== AUTORUNS")?;

    // --- Timers ---
    writeln!(out, "--- Timers")?;

    // We handle the Result here so that if systemctl fails, we log it
    // to the output report but CONTINUE to run the Cron checks below.
    match crate::utils::scheduling::get_active_timers() {
        Ok(timers) => {
            if timers.is_empty() {
                writeln!(out, "(none)")?;
            } else {
                for timer in timers.iter().take(20) {
                    writeln!(out, "{} (Next: {})", timer.unit, timer.next_run)?;
                }
            }
        }
        Err(e) => {
            // Log to the report string so it's visible in the pager
            writeln!(out, "Error querying systemd timers: {e}")?;
            // Also log to stderr for immediate operator awareness (Teammate's request)
            eprintln!("Error querying systemd timers: {e}");
        }
    }

    // --- Cron ---
    writeln!(out, "\n--- Cron")?;
    // get_cron_entries handles its own iteration errors internally (via eprintln),
    // but returns Result if initialization (load_users) fails.
    // If load_users fails, we can't really proceed with cron checks.
    let crons = crate::utils::scheduling::get_cron_entries()?;
    if crons.is_empty() {
        writeln!(out, "(none)")?;
    } else {
        for entry in crons {
            writeln!(
                out,
                "{:<10} {} {} ({})",
                entry.user,
                entry.schedule,
                ellipsize(60, &entry.command),
                entry.source
            )?;
        }
    }

    // get_periodic_scripts returns Vec and handles errors internally
    let periodic = crate::utils::scheduling::get_periodic_scripts();
    for script in periodic {
        writeln!(out, "{} ({})", script.path, script.interval)?;
        for issue in script.findings {
            writeln!(
                out,
                "  ! {} ({}:{})",
                issue.raw_content,
                issue.filename,
                issue.line_number.unwrap_or(0)
            )?;
        }
    }

    // --- At Jobs ---
    // get_at_jobs returns Vec and handles errors internally
    let at_jobs = crate::utils::scheduling::get_at_jobs();
    if !at_jobs.is_empty() {
        writeln!(out, "\n--- At Jobs")?;
        for job in at_jobs {
            writeln!(out, "{job}")?;
        }
    }

    // --- Shell Audit ---
    writeln!(out, "\n==== SHELL AUDIT")?;

    let env_issues = crate::utils::shell_audit::audit_environment_variables();
    for issue in env_issues {
        writeln!(out, "! {} ({})", issue.raw_content, issue.filename)?;
    }

    // scan_shell_configs returns Result (load_users) but handles file access errors internally
    let shell_findings = crate::utils::shell_audit::scan_shell_configs()?;
    for issue in shell_findings {
        writeln!(
            out,
            "! {} ({}:{})",
            issue.raw_content,
            issue.filename,
            issue.line_number.unwrap_or(0)
        )?;
    }

    Ok(())
}

fn enum_containers(out: &mut impl Write) -> eyre::Result<()> {
    writeln!(out, "\n==== CONTAINER RUNTIMES")?;

    let containers = crate::utils::containers::get_containers();

    if containers.is_empty() {
        writeln!(out, "No active containers detected.")?;
    } else {
        writeln!(
            out,
            "{:<28} | {:<15} | {:<20} | {:<25} | IMAGE",
            "RUNTIME", "ID", "STATUS", "NAME"
        )?;
        writeln!(
            out,
            "{:-<28}-+-{:-<15}-+-{:-<20}-+-{:-<25}-+-{:-<20}",
            "", "", "", "", ""
        )?;

        for c in containers {
            let runtime_display = if let Some(ns) = &c.namespace {
                format!("{} ({})", c.runtime, ns)
            } else {
                c.runtime.clone()
            };

            writeln!(
                out,
                "{:<28} | {:<15} | {:<20} | {:<25} | {}",
                runtime_display,
                truncate(24, &c.name),
                c.status,
                truncate(12, &c.id),
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
    Ok(())
}

fn enum_ports(out: &mut impl Write, p: super::ports::Ports) -> eyre::Result<()> {
    writeln!(out, "\n==== PORTS INFO")?;
    p.run(out)
}
