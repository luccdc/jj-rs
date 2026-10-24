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

/// Executes a PowerShell script using `-NoProfile` and `-ExecutionPolicy Bypass`.
///
/// If the encoded script is small enough (under 8,192 characters), it uses `-EncodedCommand`.
/// For larger scripts (to avoid Windows `CreateProcess` 32,767 character command-line limit,
/// which causes OS error 206 "The filename or extension is too long"), it writes the script to
/// a temporary `.ps1` file, executes via `-File`, and ensures the temporary file is deleted.
///
/// Returns the process `Output` (exit status, stdout, stderr).
pub fn run_powershell(script: &str) -> std::io::Result<Output> {
    let encoded = encode_powershell_command(script);
    if encoded.len() <= 8192 {
        powershell_command(script).output()
    } else {
        struct TempFileGuard(std::path::PathBuf);
        impl Drop for TempFileGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_path = temp_dir.join(format!("jj_ps_{}_{}.ps1", std::process::id(), timestamp));
        std::fs::write(&temp_path, script)?;
        let _guard = TempFileGuard(temp_path.clone());
        powershell_file_command(&temp_path).output()
    }
}

/// Constructs a `Command` configured to execute a PowerShell script file:
/// `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <path>`
pub fn powershell_file_command<P: AsRef<std::path::Path>>(path: P) -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
    cmd.arg(path.as_ref());
    cmd
}

