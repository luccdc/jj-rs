//! Utilities for auditing SSH configurations and authorized keys

use crate::utils::passwd::load_users;
use std::path::Path;
use walkdir::WalkDir;

/// Security settings to check in `sshd_config`
const SSHD_CHECKS: &[(&str, &str)] = &[
    ("PermitRootLogin", "yes"),
    ("PasswordAuthentication", "yes"),
    ("PermitEmptyPasswords", "yes"),
    ("X11Forwarding", "yes"),
    ("IgnoreRhosts", "no"),
    ("HostbasedAuthentication", "yes"),
    ("PubkeyAuthentication", "yes"), // Often useful to know if enabled
];

pub struct SshKeyEntry {
    pub user: String,
    pub comment: String,
    pub path: String,
    pub key_type: String,
    pub key: String,
}

pub struct SshConfigIssue {
    pub setting: String,
    pub value: String,
    pub filename: String,
}

pub struct SshCaIssue {
    pub raw_line: String,
    pub filename: String,
}

/// Helper to get all ssh config files
fn get_ssh_configs() -> Vec<String> {
    let mut files = Vec::new();
    if Path::new("/etc/ssh/sshd_config").exists() {
        files.push("/etc/ssh/sshd_config".to_string());
    }

    let config_d = "/etc/ssh/sshd_config.d";
    if Path::new(config_d).exists() {
        for entry in WalkDir::new(config_d).max_depth(1) {
            match entry {
                Ok(e) => {
                    if e.path().extension().is_some_and(|ext| ext == "conf") {
                        files.push(e.path().to_string_lossy().to_string());
                    }
                }
                Err(err) => eprintln!("Could not access entry in {config_d}: {err}"),
            }
        }
    }
    files
}

pub fn audit_sshd_config() -> Vec<SshConfigIssue> {
    let mut issues = Vec::new();

    for path in get_ssh_configs() {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for (setting, risky_val) in SSHD_CHECKS {
                    // Find line matching setting and value
                    // We use find() to get the first occurrence in the file
                    if let Some(_line) = content.lines().find(|l| {
                        let l = l.trim();
                        !l.starts_with('#')
                            && l.to_lowercase().contains(&setting.to_lowercase())
                            && l.to_lowercase().contains(risky_val)
                    }) {
                        issues.push(SshConfigIssue {
                            setting: setting.to_string(),
                            value: risky_val.to_string(),
                            filename: path.clone(),
                        });
                    }
                }
            }
            Err(e) => eprintln!("Could not read SSH config {path}: {e}"),
        }
    }
    issues
}

pub fn audit_ssh_ca() -> Vec<SshCaIssue> {
    let mut alerts = Vec::new();
    let sensitive_keys = ["TrustedUserCAKeys", "AuthorizedPrincipalsFile"];

    for path in get_ssh_configs() {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for key in &sensitive_keys {
                    if let Some(line) = content
                        .lines()
                        .find(|l| !l.trim().starts_with('#') && l.contains(key))
                    {
                        alerts.push(SshCaIssue {
                            // Field 'key' removed as it is contained in raw_line
                            raw_line: line.trim().to_string(),
                            filename: path.clone(),
                        });
                    }
                }
            }
            Err(e) => eprintln!("Could not read SSH config {path}: {e}"),
        }
    }
    alerts
}

pub fn get_user_keys() -> eyre::Result<Vec<SshKeyEntry>> {
    let users = load_users::<_, &str>(None)?;
    let mut entries = Vec::new();

    for user in users {
        let ssh_path = Path::new(&user.home).join(".ssh/authorized_keys");
        match std::fs::read_to_string(&ssh_path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    // Standard: [options] type key comment
                    // Minimal: type key
                    if parts.len() >= 2 {
                        // Simple heuristic to find the key type (ssh-rsa, ssh-ed25519, ecdsa-...)
                        let type_idx = parts
                            .iter()
                            .position(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-"))
                            .unwrap_or(0);

                        if type_idx + 1 < parts.len() {
                            let key_type = parts[type_idx].to_string();
                            let key_val = parts[type_idx + 1].to_string(); // Capture full key

                            let comment = if parts.len() > type_idx + 2 {
                                parts[type_idx + 2..].join(" ")
                            } else {
                                String::new()
                            };

                            entries.push(SshKeyEntry {
                                user: user.user.clone(),
                                comment,
                                path: ssh_path.to_string_lossy().to_string(),
                                key_type,
                                key: key_val,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Could not read authorized_keys for {}: {e}", user.user);
                }
            }
        }
    }

    Ok(entries)
}
