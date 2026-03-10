use chrono::Utc;
use serde_json::json;
use std::{net::Ipv4Addr, process::Command};

use crate::utils::checks::{
    CheckResult, CheckValue, IntoCheckResult, Troubleshooter, TroubleshooterRunner, check_fn,
    get_system_logs, optionally_run_in_container,
};

#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct CommandTroubleshooter {
    /// The shell command line to execute (e.g. "ls -la /tmp")
    #[arg(long, short = 'C', default_value = "echo hello")]
    pub command: CheckValue,

    /// Disable the download shell used to execute the command
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,

    /// Treat this as a local-only check
    #[arg(long, short)]
    pub local: bool,
}

impl Default for CommandTroubleshooter {
    fn default() -> Self {
        CommandTroubleshooter {
            command: CheckValue::stdin(),
            disable_download_shell: false,
            sneaky_ip: None,
            local: false,
        }
    }
}

impl Troubleshooter for CommandTroubleshooter {
    fn display_name(&self) -> &'static str {
        "Command"
    }

    fn checks<'a>(
        &'a self,
    ) -> eyre::Result<Vec<Box<dyn crate::utils::checks::CheckStep<'a> + 'a>>> {
        Ok(vec![check_fn("Run shell command", |tr| {
            self.try_run_command(tr)
        })])
    }

    fn is_local(&self) -> bool {
        // This troubleshooter is conceptually local; we still keep the flag for messaging.
        self.local
    }
}

impl CommandTroubleshooter {
    pub fn try_run_command(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        // Resolve the command string (supports "-", "@/file", or literal value).
        let cmd_line = self
            .command
            .clone()
            .resolve_prompt(tr, "Enter the command to execute: ")?;

        // Mirror other troubleshooters: optionally run inside the download container and
        // get a start time for log collection.
        let (res, start) = optionally_run_in_container(
            true, // wait_1s: avoid overlapping logs with container setup
            self.disable_download_shell,
            self.sneaky_ip,
            move |_wan_ip| {
                // For now we ignore wan_ip and just run the command as given.
                // If later you want to rewrite the command for container, you can use _wan_ip.
                self.try_run_command_inner(&cmd_line)
            },
        );

        let check_result = res.into_check_result("Failed to execute shell command");
        let end = Utc::now();

        // Match other modules: only pull system logs when this is local.
        let logs = (self.local).then(|| get_system_logs(start, end));

        Ok(check_result.merge_overwrite_details(json!({
            "system_logs": logs,
        })))
    }

    fn try_run_command_inner(&self, cmd_line: &str) -> eyre::Result<CheckResult> {
        // On Unix, run via /bin/sh -c "<cmd_line>"
        // On Windows, run via cmd.exe /C "<cmd_line>"
        #[cfg(unix)]
        let mut cmd = {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(cmd_line);
            c
        };

        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd.exe");
            c.arg("/C").arg(cmd_line);
            c
        };

        let output = cmd.output()?;

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        // Treat either stdout or stderr as "output present".
        let has_output = !stdout_str.trim().is_empty() || !stderr_str.trim().is_empty();
        let success_status = output.status.success();

        let details = json!({
            "command": cmd_line,
            "exit_code": exit_code,
            "stdout": stdout_str,
            "stderr": stderr_str,
        });

        if !success_status {
            return Ok(CheckResult::fail(
                format!("Command exited with non-zero status: {exit_code}"),
                details,
            ));
        }

        if !has_output {
            return Ok(CheckResult::fail("Command produced no output", details));
        }

        Ok(CheckResult::succeed(
            "Command ran successfully and produced output",
            details,
        ))
    }
}
