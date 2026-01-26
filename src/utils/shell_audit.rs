//! Utilities for auditing shell environments for suspicious variables and shadowing

use crate::utils::passwd::load_users;
use std::path::Path;

pub struct ShellFindings {
    pub path: String,
    pub user: String,
    pub alerts: Vec<String>,
}

const SUS_KEYWORDS: &[&str] = &[
    "curl", "wget", "nc ", "netcat", "base64", "python", "perl", "/dev/tcp", "bash -i",
];
const CORE_UTILS: &[&str] = &[
    "ls", "cd", "sudo", "cat", "ps", "netstat", "ip", "ss", "whoami",
];

pub fn audit_environment_variables() -> Vec<String> {
    let mut alerts = Vec::new();

    let watched_vars = [
        ("LD_PRELOAD", "Possible library injection"),
        ("PROMPT_COMMAND", "Executes on every shell prompt"),
        (
            "PS1",
            "Potential shell hijacking/obfuscation via escape codes",
        ),
        ("PYTHONPATH", "Python module hijacking"),
    ];

    for (var, desc) in &watched_vars {
        if let Ok(val) = std::env::var(var)
            && !val.is_empty()
        {
            alerts.push(format!("[!] {var} found: {val} ({desc})"));
        }
    }

    alerts
}

pub fn scan_shell_configs() -> eyre::Result<Vec<ShellFindings>> {
    let users = load_users::<_, &str>(None)?;
    let mut report = Vec::new();
    let global_configs = [
        "/etc/bash.bashrc",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/environment",
    ];

    for config in &global_configs {
        if let Some(alerts) = audit_file(Path::new(config)) {
            report.push(ShellFindings {
                path: (*config).to_string(),
                user: "system-wide".to_string(),
                alerts,
            });
        }
    }

    for user in users {
        let user_configs = [
            ".bashrc",
            ".profile",
            ".bash_profile",
            ".zshrc",
            ".zprofile",
            ".bash_logout",
            ".zlogout",
            ".xinitrc",
            ".xsession",
        ];

        for conf_name in &user_configs {
            let path = Path::new(&user.home).join(conf_name);
            if let Some(alerts) = audit_file(&path) {
                report.push(ShellFindings {
                    path: path.to_string_lossy().to_string(),
                    user: user.user.clone(),
                    alerts,
                });
            }
        }
    }
    Ok(report)
}

fn audit_file(path: &Path) -> Option<Vec<String>> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    let mut alerts = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        for key in SUS_KEYWORDS {
            if trimmed.contains(key) {
                alerts.push(format!("Found sensitive keyword '{key}': {trimmed}"));
            }
        }

        if trimmed.starts_with("alias ") {
            for util in CORE_UTILS {
                let pattern = format!("alias {util}=");
                if trimmed.contains(&pattern) {
                    alerts.push(format!(
                        "Utility shadowing detected: '{util}' is aliased to '{trimmed}'"
                    ));
                }
            }
        }
    }

    if alerts.is_empty() {
        None
    } else {
        Some(alerts)
    }
}
