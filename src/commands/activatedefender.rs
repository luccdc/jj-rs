use colored::*;
use std::io::Write;

use crate::utils::pager::{self, PagerOutput};
use crate::utils::run_powershell;

const SHIELDS_UP_SCRIPT: &str = include_str!("shieldsup/shieldsup.ps1");
const CHECK_PERMS_SCRIPT: &str = include_str!("shieldsup/checkperms.ps1");

/// Harden Windows Defender, Firewall, and security registry settings
#[derive(clap::Parser, Clone, Debug, Default)]
pub struct ShieldsUp {
    /// Check permissions, existence, and ownership of Defender and Firewall registry keys
    #[arg(short = 'c', long)]
    pub checkperms: bool,
}

impl super::Command for ShieldsUp {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        if self.checkperms {
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
