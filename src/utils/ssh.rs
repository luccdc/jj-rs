//! Utilities for auditing SSH configurations and authorized keys

use crate::utils::passwd::load_users;
use std::path::Path;

/// Security settings to check in `sshd_config`
const SSHD_CHECKS: &[(&str, &str)] = &[
    ("PermitRootLogin", "yes"),
    ("PasswordAuthentication", "yes"),
    ("PermitEmptyPasswords", "yes"),
    ("X11Forwarding", "yes"),
];

pub struct SshKeyInfo {
    pub user: String,
    pub key_count: usize,
    pub path: String,
}

/// Audit the SSH daemon configuration for risky settings
pub fn audit_sshd_config() -> Vec<String> {
    let config_path = "/etc/ssh/sshd_config";
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return vec![format!("Could not read {config_path}")];
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
                .map(|_| format!("Potentially risky setting found: {setting} is {risky_val}"))
        })
        .collect()
}

/// Scan all users for `authorized_keys` files and count valid entries
pub fn get_user_keys() -> eyre::Result<Vec<SshKeyInfo>> {
    // Specify generic arguments to fix inference error E0283
    let users = load_users::<_, &str>(None)?;
    let mut keys = Vec::new();

    for user in users {
        let ssh_path = Path::new(&user.home).join(".ssh/authorized_keys");
        if let Ok(content) = std::fs::read_to_string(&ssh_path) {
            let count = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .count();

            if count > 0 {
                keys.push(SshKeyInfo {
                    user: user.user,
                    key_count: count,
                    path: ssh_path.to_string_lossy().to_string(),
                });
            }
        }
    }

    Ok(keys)
}
