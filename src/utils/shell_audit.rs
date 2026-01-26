//! Utilities for auditing shell environments for suspicious variables and shadowing

use crate::utils::passwd::load_users;
use std::path::Path;

/// Categorizes the type of anomaly found in a shell configuration
#[derive(Debug, Clone)]
pub enum ShellIssueType {
    SuspiciousEnvVar,
    SensitiveKeyword,
    AliasShadowing,
}

/// A specific finding within a shell file or environment
#[derive(Debug, Clone)]
pub struct ShellIssue {
    pub issue_type: ShellIssueType,
    pub description: String,
    pub raw_content: String,
    pub line_number: Option<usize>,
}

/// Aggregates findings for a specific file/user
pub struct ShellFindings {
    pub path: String,
    pub user: String,
    pub issues: Vec<ShellIssue>,
}

const SUS_KEYWORDS: &[&str] = &[
    "curl", "wget", "nc ", "netcat", "base64", "python", "perl", "/dev/tcp", "bash -i",
];
const CORE_UTILS: &[&str] = &[
    "ls", "cd", "sudo", "cat", "ps", "netstat", "ip", "ss", "whoami",
];

pub fn audit_environment_variables() -> Vec<ShellIssue> {
    let mut issues = Vec::new();

    let watched_vars = [
        ("LD_PRELOAD", "Possible library injection"),
        ("PROMPT_COMMAND", "Executes on every shell prompt"),
        ("PS1", "Potential shell hijacking/obfuscation via escape codes"),
        ("PYTHONPATH", "Python module hijacking"),
    ];

    for (var, desc) in &watched_vars {
        if let Ok(val) = std::env::var(var)
            && !val.is_empty()
        {
            issues.push(ShellIssue {
                issue_type: ShellIssueType::SuspiciousEnvVar,
                description: desc.to_string(),
                raw_content: format!("{var}={val}"),
                line_number: None,
            });
        }
    }

    issues
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
        let issues = audit_file(Path::new(config));
        if !issues.is_empty() {
            report.push(ShellFindings {
                path: (*config).to_string(),
                user: "system-wide".to_string(),
                issues,
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
            let issues = audit_file(&path);
            if !issues.is_empty() {
                report.push(ShellFindings {
                    path: path.to_string_lossy().to_string(),
                    user: user.user.clone(),
                    issues,
                });
            }
        }
    }
    Ok(report)
}

fn audit_file(path: &Path) -> Vec<ShellIssue> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut issues = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        for key in SUS_KEYWORDS {
            if trimmed.contains(key) {
                issues.push(ShellIssue {
                    issue_type: ShellIssueType::SensitiveKeyword,
                    description: format!("Found sensitive keyword '{key}'"),
                    raw_content: trimmed.to_string(),
                    line_number: Some(idx + 1),
                });
            }
        }

        if trimmed.starts_with("alias ") {
            for util in CORE_UTILS {
                let pattern = format!("alias {util}=");
                if trimmed.contains(&pattern) {
                    issues.push(ShellIssue {
                        issue_type: ShellIssueType::AliasShadowing,
                        description: format!("Utility '{util}' is shadowed by alias"),
                        raw_content: trimmed.to_string(),
                        line_number: Some(idx + 1),
                    });
                }
            }
        }
    }

    issues
}
