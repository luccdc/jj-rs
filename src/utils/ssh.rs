//! Utilities for auditing SSH configurations and authorized keys

use crate::utils::passwd::load_users;
use std::path::Path;

/// Security settings to check in `sshd_config`
const SSHD_CHECKS: &[(&str, &str)] = &[
    ("PermitRootLogin", "yes"),
    ("PasswordAuthentication", "yes"),
    ("PermitEmptyPasswords", "yes"),
    ("X11Forwarding", "yes"),
    ("IgnoreRhosts", "no"),
    ("HostbasedAuthentication", "yes"),
];

pub struct SshKeyEntry {
    pub user: String,
    pub comment: String,
    pub path: String,
}

/// Represents a specific configuration line that might be dangerous
pub struct SshConfigIssue {
    pub setting: String,
    pub value: String,
    pub raw_line: String,
}

/// Represents a Certificate Authority or Principal setting
pub struct SshCaIssue {
    pub key: String,
    pub raw_line: String,
}

/// Audit the SSH daemon configuration for risky settings
pub fn audit_sshd_config() -> Vec<SshConfigIssue> {
    let config_path = "/etc/ssh/sshd_config";
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };

    SSHD_CHECKS
        .iter()
        .filter_map(|(setting, risky_val)| {
            content
                .lines()
                .find(|l| {
                    let l = l.trim();
                    !l.starts_with('#')
                        && l.to_lowercase().contains(&setting.to_lowercase())
                        && l.to_lowercase().contains(risky_val)
                })
                .map(|line| SshConfigIssue {
                    setting: setting.to_string(),
                    value: risky_val.to_string(),
                    raw_line: line.trim().to_string(),
                })
        })
        .collect()
}

pub fn audit_ssh_ca() -> Vec<SshCaIssue> {
    let config_path = "/etc/ssh/sshd_config";
    let mut alerts = Vec::new();
    if let Ok(content) = std::fs::read_to_string(config_path) {
        let sensitive_keys = ["TrustedUserCAKeys", "AuthorizedPrincipalsFile"];
        for key in &sensitive_keys {
            if let Some(line) = content
                .lines()
                .find(|l| !l.trim().starts_with('#') && l.contains(key)) 
            {
                alerts.push(SshCaIssue {
                    key: key.to_string(),
                    raw_line: line.trim().to_string(),
                });
            }
        }
    }
    alerts
}

/// Scan all users for `authorized_keys` files and extract key identities
pub fn get_user_keys() -> eyre::Result<Vec<SshKeyEntry>> {
    let users = load_users::<_, &str>(None)?;
    let mut entries = Vec::new();

    for user in users {
        let ssh_path = Path::new(&user.home).join(".ssh/authorized_keys");
        if let Ok(content) = std::fs::read_to_string(&ssh_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                // Standard format: [options] <type> <key> <comment>
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    entries.push(SshKeyEntry {
                        user: user.user.clone(),
                        comment: parts.last().unwrap_or(&"no-comment").to_string(),
                        path: ssh_path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }

    Ok(entries)
}
