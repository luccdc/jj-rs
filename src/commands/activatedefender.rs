use colored::*;
use std::io::Write;

use crate::utils::pager::{self, PagerOutput};
use crate::utils::run_powershell;

const SHIELDS_UP_SCRIPT: &str = include_str!("shieldsup/shieldsup.ps1");
const CHECK_PERMS_SCRIPT: &str = include_str!("shieldsup/checkperms.ps1");
const YOLO_SCRIPT: &str = include_str!("shieldsup/yolo.ps1");

/// Harden Windows Defender, Firewall, and security registry settings
#[derive(clap::Parser, Clone, Debug, Default)]
pub struct ShieldsUp {
    /// Check permissions, existence, and ownership of Defender and Firewall registry keys
    #[arg(short = 'c', long)]
    pub checkperms: bool,

    /// Audit, remediate locked permissions/ownership, and enforce Shields Up security configuration
    #[arg(short = 'y', long)]
    pub yolo: bool,
}

impl super::Command for ShieldsUp {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        if self.yolo {
            run_yolo_remediation(&mut ob)?;
        } else if self.checkperms {
            check_registry_permissions(&mut ob)?;
        } else {
            activate_shields_up(&mut ob)?;
        }

        Ok(())
    }
}

/// Check permissions, existence, and ownership of Defender and Firewall registry paths
fn check_registry_permissions(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== REGISTRY PERMISSIONS & INTEGRITY AUDIT (SHIELDS UP)")?;

    let output = run_powershell(CHECK_PERMS_SCRIPT)?;

    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    let mut current_category = String::new();
    let mut green_count = 0;
    let mut yellow_count = 0;

    for line in trimmed.lines() {
        let line = line.trim();
        if line.starts_with("STATUS_EXISTS:") {
            let data = line.replace("STATUS_EXISTS:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 11 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let owner = parts[3].trim();
                let is_trusted = parts[4].trim().eq_ignore_ascii_case("true");
                let deny_count: usize = parts[5].trim().parse().unwrap_or(0);
                let deny_details = parts[6].trim();
                let _access_ok = parts[7].trim().eq_ignore_ascii_case("true");
                let can_write = parts[8].trim().eq_ignore_ascii_case("true");
                let bad_values = parts[9].trim();
                let is_healthy = parts[10].trim().eq_ignore_ascii_case("true");

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                if is_healthy {
                    green_count += 1;
                    writeln!(out, "{}", format!("  [+] {} [{}]", path, desc).green())?;
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      Owner: {} [OK] | Admin Access: OK | Deny Rules: None",
                            owner
                        )
                        .green()
                    )?;
                } else {
                    yellow_count += 1;
                    writeln!(
                        out,
                        "{}",
                        format!("  [!] {} [{}]", path, desc).yellow().bold()
                    )?;
                    if !is_trusted {
                        writeln!(
                            out,
                            "{}",
                            format!(
                                "      [!] Owner: {} (Improper Owner - Expected SYSTEM, Administrators, or TrustedInstaller)",
                                owner
                            )
                            .yellow()
                        )?;
                    } else {
                        writeln!(out, "{}", format!("      [+] Owner: {} [OK]", owner).green())?;
                    }

                    if deny_count > 0 {
                        writeln!(
                            out,
                            "{}",
                            format!("      [!] Deny Rules: {}", deny_details).yellow()
                        )?;
                    }

                    if !can_write && !path.contains("SOFTWARE\\Microsoft\\Windows Defender") {
                        writeln!(
                            out,
                            "{}",
                            "      [!] Admin Access: Cannot write / modify key!".yellow()
                        )?;
                    }

                    if !bad_values.is_empty() {
                        writeln!(
                            out,
                            "{}",
                            format!("      [!] Tampered Security Values: {}", bad_values).yellow()
                        )?;
                    }
                }
            }
        } else if line.starts_with("STATUS_DENIED:") {
            yellow_count += 1;
            let data = line.replace("STATUS_DENIED:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 4 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let err = parts[3].trim();

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                writeln!(
                    out,
                    "{}",
                    format!("  [!] {} [{}]", path, desc).yellow().bold()
                )?;
                writeln!(
                    out,
                    "{}",
                    "      [!] Access Denied: Administrator locked out from reading security descriptor!"
                        .yellow()
                )?;
                writeln!(out, "{}", format!("      [!] Error: {}", err).yellow())?;
            }
        } else if line.starts_with("STATUS_MISSING:") {
            yellow_count += 1;
            let data = line.replace("STATUS_MISSING:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 7 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let parent = parts[3].trim();
                let _parent_exists = parts[4].trim().eq_ignore_ascii_case("true");
                let parent_owner = parts[5].trim();
                let parent_can_write = parts[6].trim().eq_ignore_ascii_case("true");

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                writeln!(out, "{}", format!("  [!] {} [{}]", path, desc).yellow())?;
                if !parent_can_write {
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      [!] Key does not exist & parent '{}' is blocked from writes (Owner: {})",
                            parent, parent_owner
                        )
                        .yellow()
                    )?;
                } else {
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      [!] Key does not exist (Parent '{}' is accessible)",
                            parent
                        )
                        .yellow()
                    )?;
                }
            }
        }
    }

    // Summary Section
    writeln!(out, "\n==== REGISTRY AUDIT SUMMARY")?;
    writeln!(
        out,
        "{}",
        format!("  Properly Owned & Accessible (Green): {}", green_count).green().bold()
    )?;
    if yellow_count == 0 {
        writeln!(
            out,
            "{}",
            "  Improperly Owned / Missing / Inaccessible (Yellow): 0".green()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            format!(
                "  Improperly Owned / Missing / Inaccessible (Yellow): {}",
                yellow_count
            )
            .yellow()
            .bold()
        )?;
    }

    Ok(())
}

/// Apply Shields Up security hardening for Defender and Firewall
fn activate_shields_up(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== ACTIVATING SHIELDS UP (WINDOWS DEFENDER & FIREWALL)")?;

    let output = run_powershell(SHIELDS_UP_SCRIPT)?;

    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    if trimmed.contains("SHIELDS_UP_SUCCESS") {
        writeln!(
            out,
            "{}",
            "[+] Shields Up applied! Windows Defender, Firewall, and security policies are active."
                .green()
                .bold()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            "  [!] Shields Up encountered errors setting some registry properties:".red().bold()
        )?;
        for line in trimmed.lines() {
            let line = line.trim();
            if line.starts_with("ERROR:") {
                writeln!(out, "      {}", line.replace("ERROR:", "").trim().red())?;
            }
        }
        writeln!(
            out,
            "{}",
            "  [!] Permissions may be locked. Run 'jj shieldsup --checkperms' to inspect registry permissions."
                .yellow()
        )?;
    }

    Ok(())
}

/// Audit, remediate locked permissions/ownership, and enforce Shields Up security configuration
fn run_yolo_remediation(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(
        out,
        "\n==== YOLO MODE: AUDITING & REMEDIATING WINDOWS DEFENDER & FIREWALL ===="
    )?;

    let output = run_powershell(YOLO_SCRIPT)?;
    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    let mut current_category = String::new();
    let mut audit_issues = Vec::new();
    let mut repaired_perms = Vec::new();
    let mut settings_applied = Vec::new();
    let mut service_states = Vec::new();
    let mut error_messages = Vec::new();
    let mut stats = None;

    for line in trimmed.lines() {
        let line = line.trim();
        if line.starts_with("AUDIT_ISSUE:") {
            let data = line.replace("AUDIT_ISSUE:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 4 {
                audit_issues.push((
                    parts[0].trim().to_string(),
                    parts[1].trim().to_string(),
                    parts[2].trim().to_string(),
                    parts[3].trim().to_string(),
                ));
            }
        } else if line.starts_with("REPAIRED_PERMS:") {
            let data = line.replace("REPAIRED_PERMS:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 2 {
                repaired_perms.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
            }
        } else if line.starts_with("SETTING_APPLIED:") {
            let desc = line.replace("SETTING_APPLIED:", "").trim().to_string();
            settings_applied.push(desc);
        } else if line.starts_with("SERVICE_STATE:") {
            let data = line.replace("SERVICE_STATE:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 2 {
                service_states.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
            }
        } else if line.starts_with("ERROR:") {
            let err = line.replace("ERROR:", "").trim().to_string();
            error_messages.push(err);
        } else if line.starts_with("YOLO_DONE:") {
            let data = line.replace("YOLO_DONE:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 4 {
                let total: usize = parts[0].trim().parse().unwrap_or(0);
                let bad: usize = parts[1].trim().parse().unwrap_or(0);
                let fixed: usize = parts[2].trim().parse().unwrap_or(0);
                let errs: usize = parts[3].trim().parse().unwrap_or(0);
                stats = Some((total, bad, fixed, errs));
            }
        }
    }

    // Phase 1: Audit Report
    writeln!(out, "\n[*] Phase 1: Registry Audit Findings")?;
    if audit_issues.is_empty() {
        writeln!(
            out,
            "{}",
            "  [+] All target registry keys exist with clean permissions and trusted ownership."
                .green()
        )?;
    } else {
        for (cat, path, desc, issue) in &audit_issues {
            if *cat != current_category {
                current_category = cat.clone();
                writeln!(out, "\n  [Category] {}", current_category.cyan().bold())?;
            }
            writeln!(out, "{}", format!("    [!] {} [{}]", path, desc).yellow().bold())?;
            writeln!(out, "{}", format!("        Issue: {}", issue).yellow())?;
        }
    }

    // Phase 2: Remediation Report
    writeln!(out, "\n[*] Phase 2: Permission & Ownership Remediation")?;
    if repaired_perms.is_empty() {
        writeln!(
            out,
            "{}",
            "  [+] No permission remediation was required; administrators already had write access."
                .green()
        )?;
    } else {
        for (path, fixes) in &repaired_perms {
            writeln!(out, "{}", format!("  [+] Fixed: {}", path).green().bold())?;
            writeln!(out, "{}", format!("      Actions: {}", fixes).green())?;
        }
    }

    // Phase 3: Enforced Hardening Policies
    writeln!(out, "\n[*] Phase 3: Applied Hardening Policies & Settings")?;
    for setting in &settings_applied {
        writeln!(out, "{}", format!("  [+] {}", setting).green())?;
    }

    // Phase 4: Service States
    writeln!(out, "\n[*] Phase 4: Security Services Verification")?;
    for (svc, state) in &service_states {
        if state.eq_ignore_ascii_case("Running") {
            writeln!(out, "{}", format!("  [+] Service '{}': {}", svc, state).green().bold())?;
        } else {
            writeln!(out, "{}", format!("  [!] Service '{}': {}", svc, state).yellow().bold())?;
        }
    }

    // Errors (if any)
    if !error_messages.is_empty() {
        writeln!(
            out,
            "\n{}",
            "  [!] Errors encountered during execution:".red().bold()
        )?;
        for err in &error_messages {
            writeln!(out, "{}", format!("      [!] {}", err).red())?;
        }
    }

    // Summary Section
    writeln!(out, "\n==== YOLO REMEDIATION SUMMARY")?;
    if let Some((total, bad, fixed, errs)) = stats {
        writeln!(out, "  Total Keys Audited: {}", total)?;
        writeln!(out, "{}", format!("  Issues Detected:    {}", bad).yellow())?;
        writeln!(out, "{}", format!("  Keys Remediated:    {}", fixed).green().bold())?;
        if errs == 0 {
            writeln!(out, "{}", "  Errors:             0".green())?;
            writeln!(
                out,
                "\n{}",
                "[+] SHIELDS UP ACTIVE: All registry permissions, Defender, and Firewall services are restored!"
                    .green()
                    .bold()
            )?;
        } else {
            writeln!(out, "{}", format!("  Errors:             {}", errs).red().bold())?;
            writeln!(
                out,
                "\n{}",
                "  [!] Completed with warnings. Inspect the errors above."
                    .yellow()
                    .bold()
            )?;
        }
    } else {
        writeln!(out, "{}", "[+] YOLO execution finished.".green().bold())?;
    }

    Ok(())
}
