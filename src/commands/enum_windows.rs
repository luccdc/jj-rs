use std::io::Write;

use clap::{Parser, Subcommand};

use crate::utils::{
    logs::{ellipsize, truncate},
    pager::{self, PagerOutput},
    qx,
};

/// Perform system enumeration or target specific subsystems
#[derive(Parser, Debug)]
#[command(about = "System enumeration tools")]
pub struct Enum {
    #[arg(short, long)]
    pub output: Option<String>,
    
    /// Search for DLLs, BATs, and PS1s in addition to EXEs
    #[arg(short = 'd', long)]
    pub detailed: bool,

    /// Perform an extended scan (e.g., read file contents for web shells)
    #[arg(short = 'e', long)]
    pub extended: bool,

    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumSubcommands {
    /// Current network ports and listening services
    #[command(visible_alias("p"))]
    Ports(super::ports::Ports),
    /// Check WSL and Docker status
    WslDocker,
    /// Enumerate IIS sites and scan for potential web shells
    IisSites {
        /// Perform an extended content scan for web shells
        #[arg(short = 'e', long)]
        extended: bool,
    },
    /// Check for python web servers
    PythonSites,
    /// Enumerate FTP servers (IIS and FileZilla)
    FtpSites,
    /// Enumerate suspicious startup items
    Autoruns,
    /// Enumerate suspicious or unsigned files in System32
    System32Unsigned {
        /// Search for DLLs, BATs, and PS1s in addition to EXEs
        #[arg(short = 'd', long)]
        detailed: bool,
    },
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        // Always run Hostname enumeration
        enum_hostname(&mut ob)?;

        match self.subcommand {
            // Run a specific subsystem if a subcommand is provided
            Some(EnumSubcommands::Ports(ports)) => enum_ports(&mut ob, ports)?,
            Some(EnumSubcommands::WslDocker) => enum_wsl_docker(&mut ob)?,
            
            // Pass the extended flag here
            Some(EnumSubcommands::IisSites { extended }) => enum_iis_sites(&mut ob, self.extended || extended)?,
            
            Some(EnumSubcommands::PythonSites) => enum_python_sites(&mut ob)?,
            Some(EnumSubcommands::FtpSites) => enum_ftp_sites(&mut ob)?,
            Some(EnumSubcommands::Autoruns) => enum_startup_items(&mut ob)?,
            Some(EnumSubcommands::System32Unsigned { detailed }) => {
                enum_system32_unsigned(&mut ob, self.detailed || detailed)?
            }
            
            // Default behavior: Run all enumerations if no subcommand is given
            None => {
                // Standard Enumeration
                enum_ports(&mut ob, super::ports::Ports::default())?; 
                
                // Security & Environment
                enum_wsl_docker(&mut ob)?;
                
                // Web & Services - Pass the global extended flag here
                enum_iis_sites(&mut ob, self.extended)?;
                
                enum_python_sites(&mut ob)?;
                enum_ftp_sites(&mut ob)?;
                
                // Persistence & Files
                enum_startup_items(&mut ob)?;
                enum_system32_unsigned(&mut ob, self.detailed)?;
            }
        }

        Ok(())
    }
}

// Enumerate ports and associated PID's on the device
fn enum_ports(out: &mut impl PagerOutput, p: super::ports::Ports) -> eyre::Result<()> {
    writeln!(out, "\n==== PORTS INFO")?;
    p.run(out)
}

//Hostname enumeration ('H' alias)
fn enum_hostname(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== HOSTNAME INFO")?;

    let name = std::env::var("COMPUTERNAME")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unable to read hostname".to_string());

    writeln!(out, "Hostname: {name}")?;
    Ok(())
}

// Check if a tool exists in the user's path
fn tool_exists(tool: &str) -> bool {
    // Check if the executable exists in any folder listed in the PATH environment variable
    if let Ok(path) = std::env::var("PATH") {
        for p in std::env::split_paths(&path) {
            let p_str = p.join(format!("{}.exe", tool));
            if p_str.exists() {
                return true;
            }
        }
    }
    false
}

// Enumerate if WSL or docker is in the user's path
fn enum_wsl_docker(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== WSL / DOCKER")?;

    // WSL Check
    if std::path::Path::new(r#"C:\Windows\System32\wsl.exe"#).exists() {
        writeln!(out, "WSL Feature is installed")?;
    } else {
        writeln!(out, "WSL not found or is not in your PATH")?;
    }

    // Docker Check using our new helper
    if tool_exists("docker") {
        writeln!(out, "Docker is installed")?;
    } else {
        writeln!(out, "Docker not detected or not in your PATH")?;
    }

    Ok(())
}

// Enumerate IIS sites, listing out where they are being hosted and ports
// Enumerate IIS sites, listing out where they are being hosted and ports
fn enum_iis_sites(out: &mut impl PagerOutput, extended_scan: bool) -> eyre::Result<()> {
    writeln!(out, "\n==== IIS SITES")?;
    // We build the PowerShell script as a single string
    let script = "Import-Module WebAdministration; Get-Website | ForEach-Object { $_.PhysicalPath }";
    let output = std::process::Command::new("powershell.exe")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?; // .output() waits for the process to finish and captures stdout

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout);
        let trimmed = result.trim();
        if trimmed.is_empty() {
            writeln!(out, "No IIS sites found.")?;
        } else {
            for line in trimmed.lines() {
                let path = line.trim();
                // Ensure it's a valid looking path before scanning
                if !path.is_empty() && path.contains(':') {
                    writeln!(out, "Found Site Path: {}", path)?;
                    
                    // PASS THE FLAG HERE!
                    scan_web_files(out, path, extended_scan)?;
                }
            }
        }
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        writeln!(out, "PowerShell Error: {}", err)?;
    }
    Ok(())
}

use walkdir::WalkDir;
use colored::*;
use regex::Regex;
use std::fs;

// Assuming PagerOutput is a custom trait in your codebase that implements standard formatting.
// If it's standard IO, you can replace `impl PagerOutput` with `impl std::fmt::Write` or `impl std::io::Write`.

pub fn scan_web_files(out: &mut impl PagerOutput, root: &str, extended_scan: bool) -> eyre::Result<()> {
    // 1. Clean the path
    let clean_root = root.trim_matches(|c| c == '\"' || c == ' ');
    
    if !std::path::Path::new(clean_root).exists() {
        return Ok(());
    }

    writeln!(out, "Scanning directory: {}", clean_root)?;

    // 2. Define target extensions and signatures
    let danger_exts = ["php", "aspx", "asp", "jsp", "jspx", "cfm", "ashx", "asax", "html"];
    let pii_exts = ["csv", "txt", "xls", "xlsx"];
    
    // Signatures for extended content scanning
    let content_sigs = [
        "eval(", 
        "base64_decode(", 
        "System.Diagnostics.Process", 
        "cmd.exe", 
        "WScript.Shell",
        "xp_cmdshell"
    ];

    // Compile regex outside the loop for performance.
    // This catches variations like sh3ll, $hell, p0ny, b374k, etc.
    let shell_regex = Regex::new(
    r"(?i)(?:[s$][^a-zA-Z0-9]{0,2}[h][^a-zA-Z0-9]{0,2}[e3][^a-zA-Z0-9]{0,2}[l1][^a-zA-Z0-9]{0,2}[l1]|p[^a-zA-Z0-9]{0,2}[o0][^a-zA-Z0-9]{0,2}ny|b374k|c99|r57|backd[o0]{2}r)"
    ).unwrap();

    let exec_regex = Regex::new(
    r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\("
    ).unwrap();

    let input_regex = Regex::new(
    r"(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER)"
    ).unwrap();

// Strong indicator: execution using user input
    let webshell_combo_regex = Regex::new(
    r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)"
    ).unwrap();

// Obfuscation / encoding tricks
    let obfuscation_regex = Regex::new(
    r"(?i)(base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|eval\s*\()"
    ).unwrap();
    
    // 3. Walk the directory
    for entry in WalkDir::new(clean_root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        // Skip directories, we only want to evaluate files
        if !path.is_file() {
            continue;
        }
        
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            // --- FEATURE 3: Check for PII Files ---
            if pii_exts.contains(&ext_lower.as_str()) {
                writeln!(
                    out, 
                    "{}", 
                    format!("  [$] Potential PII file: {}", path.display()).green()
                )?;
                continue; 
            }

            // --- FEATURE 1 & 2: Check for Web Shells ---
            if danger_exts.contains(&ext_lower.as_str()) {
                let file_name = path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                // Check against regex for obfuscated names
                let mut is_sus = shell_regex.is_match(&file_name);

                // If the name isn't suspicious, but the -e flag is passed, scan the content
                if !is_sus && extended_scan {
                    if let Ok(content) = fs::read_to_string(path) {
                        let content_lower = content.to_lowercase();

                        // 1. Strong direct match (best signal)
                        if webshell_combo_regex.is_match(&content_lower) {
                            is_sus = true;
                        }
                        // 2. Execution functions alone (medium signal)
                        else if exec_regex.is_match(&content_lower) && input_regex.is_match(&content_lower) {
                            is_sus = true;
                        }
                        // 3. Obfuscation patterns
                        else if obfuscation_regex.is_match(&content_lower) {
                            is_sus = true;
                        }
                        // 4. Fallback to your original signatures
                        else {
                            is_sus = content_sigs.iter().any(|&sig| content_lower.contains(sig));
                        }
                    }
                }

                if is_sus {
                    writeln!(
                        out, 
                        "{}", 
                        format!("!!! POSSIBLE WEB SHELL: {}", path.display()).red().bold()
                    )?;
                } else if ext_lower == "php" || ext_lower == "aspx" {
                    // Just list normal web files so you know the scanner is working
                    writeln!(out, "  [+] Web file: {}", path.display())?;
                }
            }
        }
    }
    Ok(())
}

// Check for python web servers
fn enum_python_sites(out: &mut impl PagerOutput) -> eyre::Result<()> {

    writeln!(out, "\n==== PYTHON WEB SERVERS")?;

    let (_, ps) = qx("wmic process get CommandLine")?;

    for line in ps.lines() {

        if line.contains("flask")
            || line.contains("django")
            || line.contains("uvicorn")
            || line.contains("gunicorn")
            || line.contains("http.server")
        {
            writeln!(out, "Python web process: {}", ellipsize(200, line))?;
        }
    }

    Ok(())
}

// Check startup items, similar to autoruns. Ignore Microsoft ones
fn enum_startup_items(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== SUSPICIOUS STARTUP ITEMS")?;

    let script = r#"
        $locations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
        )
        foreach ($loc in $locations) {
            Get-ItemProperty $loc -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object {
                $name = $_.Name
                $val = (Get-ItemProperty $loc).$name
                if ($val -notlike "*Microsoft*" -and $val -match '\.(exe|dll|bat|ps1|py)') {
                    "Registry ($loc): $name -> $val"
                }
            }
        }
        # Check Startup Folders
        $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")
        foreach ($f in $folders) {
            Get-ChildItem $f -File | ForEach-Object { "Folder ($f): $($_.Name)" }
        }
    "#;

    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", script])
        .output()?;
    
    writeln!(out, "{}", String::from_utf8_lossy(&output.stdout).trim())?;
    Ok(())
}

// Enumerate FTP sites
fn enum_ftp_sites(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== FTP SERVERS (IIS & FILEZILLA)")?;

    // 1. IIS FTP Discovery
    let iis_script = r#"
        Import-Module WebAdministration -ErrorAction SilentlyContinue;
        Get-Website | Where-Object { $_.Bindings.Collection.protocol -contains "ftp" } | ForEach-Object {
            $p = $_.physicalPath;
            $b = ($_.Bindings.Collection | Where-Object { $_.protocol -eq "ftp" }).bindingInformation;
            "IIS_FTP_DATA: $($_.Name)|$p|$b"
        }
    "#;

    // 2. FileZilla Discovery
    let fz_script = r#"
        $fzSvc = Get-Service -Name "FileZilla Server" -ErrorAction SilentlyContinue
        if ($fzSvc) {
            "FZ_STATUS: $($fzSvc.Status)"
            $fzPath = "C:\Program Files\FileZilla Server\FileZilla Server.xml"
            if (Test-Path $fzPath) {
                [xml]$conf = Get-Content $fzPath
                $conf.FileZillaServer.Users.User.Option | Where-Object { $_.Name -eq "Directory" } | ForEach-Object { "FZ_FTP_PATH: $($_.InnerText)" }
            }
        }
    "#;

    let combined_script = format!("{}\n{}", iis_script, fz_script);

    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", &combined_script])
        .output()?;

    let res = String::from_utf8_lossy(&output.stdout);
    let mut found = false;

    for line in res.lines() {
        let line = line.trim();
        
        if line.starts_with("IIS_FTP_DATA:") {
            let data = line.replace("IIS_FTP_DATA:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 3 {
                writeln!(out, "[!] IIS FTP Site: {} | Listen: {} | Root: {}", parts[0].trim(), parts[2].trim(), parts[1].trim())?;
                found = true;
            }
        } 
        else if line.starts_with("FZ_STATUS:") {
            writeln!(out, "[+] FileZilla Service is {}", line.replace("FZ_STATUS:", "").trim())?;
            found = true;
        } 
        else if line.starts_with("FZ_FTP_PATH:") {
            // No more "temporary value dropped" error here
            let path_owned = line.replace("FZ_FTP_PATH:", "");
            writeln!(out, "[!] FileZilla FTP Root Found: {}", path_owned.trim())?;
            found = true;
        }
    }

    if !found {
        writeln!(out, "No FTP servers detected.")?;
    }

    Ok(())
}

// Check System32 for unsigned dll's, exe's, or .ps1's. without -d just checks for .exe
fn enum_system32_unsigned(out: &mut impl PagerOutput, detailed: bool) -> eyre::Result<()> {
    writeln!(out, "\n==== SUSPICIOUS FILES IN SYSTEM32")?;

    // Determine extensions based on the -d flag
    let extensions = if detailed {
        "@('*.exe', '*.dll', '*.bat', '*.ps1')"
    } else {
        "@('*.exe')"
    };

    let script = format!(
        r#"
        $extensions = {extensions}
        Get-ChildItem -Path C:\Windows\System32\* -Include $extensions | ForEach-Object {{
            $path = $_.FullName
            if ($_.Extension -match '\.(bat|ps1)') {{
                "Script Found: $path"
            }} else {{
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne 'Valid') {{
                    "Unsigned File: $path"
                }} elseif ($sig.SignerCertificate.Subject -notlike '*Microsoft*') {{
                    "Non-MS Signed: $path (Signed by: $($sig.SignerCertificate.Subject))"
                }}
            }}
        }}
        "#
    );

    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()?;

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout);
        let trimmed = result.trim();
        if trimmed.is_empty() {
            writeln!(out, "No suspicious files found.")?;
        } else {
            writeln!(out, "{}", trimmed)?;
        }
    } else {
        writeln!(out, "PowerShell Error: {}", String::from_utf8_lossy(&output.stderr))?;
    }

    Ok(())
}