use colored::*;
use std::io::Write;

use crate::utils::pager::{self, PagerOutput};
use crate::utils::{run_powershell, run_powershell_with_args};

const SHIELDS_UP_SCRIPT: &str = include_str!("shieldsup/shieldsup.ps1");

/// Audit and harden Windows Defender, Firewall, and security registry settings
#[derive(clap::Parser, Clone, Debug, Default)]
pub struct ShieldsUp {
    /// Check permissions, existence, and ownership of Defender and Firewall registry keys (default action)
    #[arg(short = 'c', long)]
    pub checkperms: bool,

    /// Audit, remediate locked permissions/ownership, and enforce Shields Up security configuration
    #[arg(short = 'y', long)]
    pub yolo: bool,
}

impl super::Command for ShieldsUp {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        let output = if self.yolo {
            run_powershell_with_args(SHIELDS_UP_SCRIPT, &["-Yolo"])?
        } else {
            run_powershell(SHIELDS_UP_SCRIPT)?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if !trimmed.is_empty() {
            writeln!(ob, "{}", trimmed)?;
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let err_trimmed = stderr.trim();
            if !err_trimmed.is_empty() {
                writeln!(ob, "{}", format!("PowerShell Error: {}", err_trimmed).red().bold())?;
            }
        }

        Ok(())
    }
}
