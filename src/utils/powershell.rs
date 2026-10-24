#![allow(dead_code)]

use base64::prelude::*;
use std::process::{Command, Output};

/// Encodes a PowerShell script into a UTF-16LE Base64 string suitable for `-EncodedCommand`.
pub fn encode_powershell_command(script: &str) -> String {
    let utf16_bytes = script
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>();
    BASE64_STANDARD.encode(&utf16_bytes)
}

/// Constructs a `Command` configured to execute a script in PowerShell:
/// `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>`
///
/// This avoids shell quoting, newline issues, and argument escaping complications.
pub fn powershell_command(script: &str) -> Command {
    let encoded = encode_powershell_command(script);
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encoded,
    ]);
    cmd
}

/// Executes a PowerShell script using `-NoProfile`, `-ExecutionPolicy Bypass`, and `-EncodedCommand`.
///
/// Returns the process `Output` (exit status, stdout, stderr).
pub fn run_powershell(script: &str) -> std::io::Result<Output> {
    powershell_command(script).output()
}

/// Constructs a `Command` configured to execute a PowerShell script file:
/// `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <path>`
pub fn powershell_file_command<P: AsRef<std::path::Path>>(path: P) -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
    cmd.arg(path.as_ref());
    cmd
}

