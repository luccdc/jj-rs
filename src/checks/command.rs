use chrono::Utc;
use serde_json::json;
use std::{net::Ipv4Addr, process::Command};

use crate::utils::checks::{
    CheckResult, IntoCheckResult, Troubleshooter, TroubleshooterRunner, check_fn, get_system_logs,
    optionally_run_in_container,
};

/// Troubleshooter that runs an arbitrary shell command and verifies it succeeds
/// and that its output contains an expected string.
///
/// This check:
/// - Executes the given command line in a shell (`/bin/sh -c` on Unix, `cmd.exe /C` on Windows).
/// - Can run inside the download container (unless disabled).
/// - Fails if the command exits with a non-zero status.
/// - Fails if the command output does not contain the expected text.
#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct CommandTroubleshooter {
    /// The shell command line to execute (e.g. "ls -la /tmp")
    #[arg(long, short = 'C', default_value = "echo hello")]
    pub command: String,

    /// Text that must appear in the command output (stdout or stderr)
    #[arg(long, short = 'E', default_value = "hello")]
    pub expected_output: String,

    /// Disable the download shell used to execute the command
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,

    /// Treat this as a local-only check (controls log collection messaging)
    #[arg(long, short)]
    pub local: bool,
}

impl Default for CommandTroubleshooter {
    fn default() -> Self {
        CommandTroubleshooter {
            command: "echo hello".to_string(),
            expected_output: "hello".to_string(),
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
            Ok(self.try_run_command(tr))
        })])
    }

    fn is_local(&self) -> bool {
        self.local
    }
}

impl CommandTroubleshooter {
    pub fn try_run_command(&self, _tr: &mut dyn TroubleshooterRunner) -> CheckResult {
        let cmd_line = self.command.clone();
        let expected = self.expected_output.clone();

        let (res, start) = optionally_run_in_container(
            true,
            self.disable_download_shell,
            self.sneaky_ip,
            move |wan_ip| try_run_command_inner(&cmd_line, &expected, wan_ip),
        );

        let check_result = res.into_check_result("Failed to execute shell command");
        let end = Utc::now();

        let logs = (self.local).then(|| get_system_logs(start, end));

        check_result.merge_overwrite_details(json!({
            "system_logs": logs,
        }))
    }
}

fn try_run_command_inner(
    cmd_line: &str,
    expected_output: &str,
    wan_ip: Option<Ipv4Addr>,
) -> eyre::Result<CheckResult> {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(cmd_line);
        c
    };

    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd.exe");
        c.arg("/c").arg(cmd_line);
        c
    };

    if let Some(ip) = wan_ip {
        cmd.env("WAN_IP", format!("{ip}"));
    }

    let output = cmd.output()?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    let details = json!({
        "command": cmd_line,
        "exit_code": exit_code,
        "stdout": stdout_str,
        "stderr": stderr_str,
        "expected_output": expected_output,
        "wan_ip": wan_ip.map(|ip| ip.to_string()),
    });

    if !output.status.success() {
        return Ok(CheckResult::fail(
            format!("Command exited with non-zero status: {exit_code}"),
            details,
        ));
    }

    let expected = expected_output.trim();
    if !expected.is_empty() && !stdout_str.contains(expected) && !stderr_str.contains(expected) {
        return Ok(CheckResult::fail(
            format!("Command output did not contain expected text: {expected}"),
            details,
        ));
    }

    Ok(CheckResult::succeed(
        "Command ran successfully and produced expected output",
        details,
    ))
}
