//! Utilities for auditing shell environments for suspicious variables and shadowing

use crate::utils::passwd::load_users;
use std::path::Path;
use walkdir::WalkDir;

/// A specific finding within a shell file or environment
#[derive(Debug, Clone)]
pub struct ShellIssue {
    pub raw_content: String,
    pub filename: String,
    pub line_number: Option<usize>,
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
        "LD_PRELOAD",
        "PROMPT_COMMAND",
        "PS1",
        "PYTHONPATH",
        "HISTFILE",
        "ENV",
        "BASH_ENV",
    ];

    for var in &watched_vars {
        if let Ok(val) = std::env::var(var)
            && !val.is_empty()
        {
            issues.push(ShellIssue {
                raw_content: format!("{var}={val}"),
                filename: "Current Env".to_string(),
                line_number: None,
            });
        }
    }

    issues
}

pub fn scan_shell_configs() -> eyre::Result<Vec<ShellIssue>> {
    let users = load_users::<_, &str>(None)?;
    let mut all_issues = Vec::new();

    // 1. Global Files
    let global_files = vec![
        "/etc/bash.bashrc",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/environment",
    ];

    for file in global_files {
        match audit_file(Path::new(file)) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => {
                if e.downcast_ref::<std::io::Error>()
                    .is_none_or(|io| io.kind() != std::io::ErrorKind::NotFound)
                {
                    eprintln!("Could not audit {file}: {e}");
                }
            }
        }
    }

    // 2. Global Directories (profile.d)
    if Path::new("/etc/profile.d").exists() {
        for entry in WalkDir::new("/etc/profile.d").max_depth(1) {
            match entry {
                Ok(e) => {
                    if e.file_type().is_file() {
                        match audit_file(e.path()) {
                            Ok(issues) => all_issues.extend(issues),
                            Err(err) => eprintln!("Could not audit {}: {err}", e.path().display()),
                        }
                    }
                }
                Err(e) => eprintln!("Error traversing /etc/profile.d: {e}"),
            }
        }
    }

    // 3. User Files
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

    for user in users {
        for conf_name in &user_configs {
            let path = Path::new(&user.home).join(conf_name);
            match audit_file(&path) {
                Ok(issues) => all_issues.extend(issues),
                // Silently ignore NotFound for user files as most won't exist
                Err(e) => {
                    if e.downcast_ref::<std::io::Error>()
                        .is_none_or(|io| io.kind() != std::io::ErrorKind::NotFound)
                    {
                        eprintln!("Could not audit {}: {e}", path.display());
                    }
                }
            }
        }
    }

    Ok(all_issues)
}

pub fn audit_file(path: &Path) -> eyre::Result<Vec<ShellIssue>> {
    let content = std::fs::read_to_string(path)?;
    let mut issues = Vec::new();
    let filename = path.to_string_lossy().to_string();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check Keywords
        for key in SUS_KEYWORDS {
            if trimmed.contains(key) {
                issues.push(ShellIssue {
                    raw_content: trimmed.to_string(),
                    filename: filename.clone(),
                    line_number: Some(idx + 1),
                });
                break; // Avoid double-flagging same line
            }
        }

        // Check Aliases
        if trimmed.starts_with("alias ") {
            for util in CORE_UTILS {
                let pattern = format!("alias {util}=");
                if trimmed.contains(&pattern) {
                    issues.push(ShellIssue {
                        raw_content: trimmed.to_string(),
                        filename: filename.clone(),
                        line_number: Some(idx + 1),
                    });
                    break;
                }
            }
        }

        // Check Exports of interest
        if trimmed.starts_with("export PATH=") || trimmed.contains("LD_PRELOAD") {
            issues.push(ShellIssue {
                raw_content: trimmed.to_string(),
                filename: filename.clone(),
                line_number: Some(idx + 1),
            });
        }
    }

    Ok(issues)
}
