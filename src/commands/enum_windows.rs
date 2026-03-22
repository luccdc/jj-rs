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
    Winrm,
    /// Enumerate local administrators and privileged local accounts
    LocalAdmins,
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        enum_hostname(&mut ob)?;

        match self.subcommand {
            Some(EnumSubcommands::Ports(ports)) => enum_ports(&mut ob, ports)?,
            Some(EnumSubcommands::WslDocker) => enum_wsl_docker(&mut ob)?,
            
            Some(EnumSubcommands::IisSites { extended }) => enum_iis_sites(&mut ob, self.extended || extended)?,
            
            Some(EnumSubcommands::PythonSites) => enum_python_sites(&mut ob)?,
            Some(EnumSubcommands::FtpSites) => enum_ftp_sites(&mut ob)?,
            Some(EnumSubcommands::Autoruns) => enum_startup_items(&mut ob)?,
            Some(EnumSubcommands::System32Unsigned { detailed }) => {
                enum_system32_unsigned(&mut ob, self.detailed || detailed)?
            }
            Some(EnumSubcommands::Winrm) => enum_winrm(&mut ob)?,
            Some(EnumSubcommands::LocalAdmins) => enum_local_admins(&mut ob)?,
            
            None => {
                enum_ports(&mut ob, super::ports::Ports::default())?; 
                
                enum_wsl_docker(&mut ob)?;
                
                enum_iis_sites(&mut ob, self.extended)?;
                
                enum_python_sites(&mut ob)?;
                enum_ftp_sites(&mut ob)?;
                
                enum_startup_items(&mut ob)?;
                enum_system32_unsigned(&mut ob, self.detailed)?;

                enum_winrm(&mut ob)?;
                enum_local_admins(&mut ob)?;
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

    if std::path::Path::new(r#"C:\Windows\System32\wsl.exe"#).exists() {
        writeln!(out, "WSL Feature is installed")?;
    } else {
        writeln!(out, "WSL not found or is not in your PATH")?;
    }

    if tool_exists("docker") {
        writeln!(out, "Docker is installed")?;
    } else {
        writeln!(out, "Docker not detected or not in your PATH")?;
    }

    Ok(())
}

// Enumerate IIS sites, listing out where they are being hosted and ports
fn enum_iis_sites(out: &mut impl PagerOutput, extended_scan: bool) -> eyre::Result<()> {
    writeln!(out, "\n==== IIS SITES")?;
    let script = "Import-Module WebAdministration; Get-Website | ForEach-Object { $_.PhysicalPath }";
    let output = std::process::Command::new("powershell.exe")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?; 

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

pub fn scan_web_files(out: &mut impl PagerOutput, root: &str, extended_scan: bool) -> eyre::Result<()> {
    let clean_root = root.trim_matches(|c| c == '\"' || c == ' ');
    
    if !std::path::Path::new(clean_root).exists() {
        return Ok(());
    }

    writeln!(out, "Scanning directory: {}", clean_root)?;

    // 1. Config & Counters
    let danger_exts = ["php", "aspx", "asp", "jsp", "jspx", "cfm", "ashx", "asax", "html"];
    let pii_exts = ["csv", "txt", "xls", "xlsx"];
    let mut web_file_count = 0;
    let max_display = 5;
    const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; 

    // 2. Optimized Regex Patterns
    let shell_regex = Regex::new(r"(?i)(?:[s$][^a-zA-Z0-9]{0,2}[h][^a-zA-Z0-9]{0,2}[e3][^a-zA-Z0-9]{0,2}[l1][^a-zA-Z0-9]{0,2}[l1]|p[^a-zA-Z0-9]{0,2}[o0][^a-zA-Z0-9]{0,2}ny|b374k|c99|r57|backd[o0]{2}r)").unwrap();
    let webshell_combo_regex = Regex::new(r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)").unwrap();
    let obfuscation_regex = Regex::new(r"(?i)(base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|eval\s*\()").unwrap();
    
    // 3. Execution
    for entry in WalkDir::new(clean_root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() { continue; }
        
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            // FEATURE: PII Check (Always Show)
            if pii_exts.contains(&ext_lower.as_str()) {
                writeln!(out, "{}", format!("  [$] Potential PII file: {}", path.display()).green())?;
                continue; 
            }

            if danger_exts.contains(&ext_lower.as_str()) {
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                let mut is_sus = false;
                let mut reason = "";

                // Check Filename Pattern
                if shell_regex.is_match(&file_name) {
                    is_sus = true;
                    reason = "Suspicious Filename";
                }

                // Check Content (-e flag)
                if !is_sus && extended_scan {
                    if let Ok(metadata) = fs::metadata(path) {
                        if metadata.len() <= MAX_FILE_SIZE {
                            if let Ok(content) = fs::read_to_string(path) {
                                let c_low = content.to_lowercase();
                                if webshell_combo_regex.is_match(&c_low) {
                                    is_sus = true;
                                    reason = "Exploit Combo Pattern";
                                } else if obfuscation_regex.is_match(&c_low) {
                                    is_sus = true;
                                    reason = "Obfuscation Detected";
                                }
                            }
                        }
                    }
                }

                // Logic for printing
                if is_sus {
                    // Backdoors ALWAYS get printed
                    writeln!(out, "{}", format!("!!! POSSIBLE WEB SHELL: {} [{}]", path.display(), reason).red().bold())?;
                } else if ext_lower == "php" || ext_lower == "aspx" {
                    // Normal files obey the "Max 5" rule
                    web_file_count += 1;
                    if web_file_count <= max_display {
                        writeln!(out, "  [+] Web file: {}", path.display())?;
                    }
                }
            }
        }
    }

    // 4. Per-site Summary
    if web_file_count > max_display {
        writeln!(out, "  [...] and {} more web files in this directory.", web_file_count - max_display)?;
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
    writeln!(out, "\n==== SUSPICIOUS STARTUP ITEMS (SIGNATURE CHECK)")?;
    let script = r#"
        $locations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
        )
        
        foreach ($loc in $locations) {
            $items = Get-ItemProperty $loc -ErrorAction SilentlyContinue
            if (-not $items) { continue }
            
            $items.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object {
                $name = $_.Name
                $val = $_.Value
                
                # Regex to extract the executable path from the command line string
                $path = ""
                if ($val -match '^"([^"]+)"') {
                    $path = $matches[1]
                } elseif ($val -match '^([^ ]+\.(exe|dll|bat|ps1|py|vbs))') {
                    $path = $matches[1]
                } else {
                    $path = $val -replace ' -.*','' # Rough fallback
                }

                if (Test-Path $path -PathType Leaf) {
                    $sig = Get-AuthenticodeSignature $path
                    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                        "Registry ($loc): $name"
                        "  -> Value: $val"
                        "  -> Status: $($sig.Status) | Signer: $($sig.SignerCertificate.Subject)"
                        ""
                    }
                } elseif ($val -match '\.(exe|dll|bat|ps1|py)') {
                    # Path was either unresolvable or had complex args, but it looks like a binary/script
                    "Unresolved Registry Path ($loc): $name"
                    "  -> Value: $val"
                    ""
                }
            }
        }
        
        # Check Startup Folders
        $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")
        foreach ($f in $folders) {
            Get-ChildItem $f -File -ErrorAction SilentlyContinue | ForEach-Object { 
                $path = $_.FullName
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                    "Folder ($f): $($_.Name)"
                    "  -> Status: $($sig.Status) | Signer: $($sig.SignerCertificate.Subject)"
                    ""
                }
            }
        }
    "#;
    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", script])
        .output()?;
    
    let res = String::from_utf8_lossy(&output.stdout);
    if res.trim().is_empty() {
        writeln!(out, "No unsigned or non-Microsoft startup items found.")?;
    } else {
        writeln!(out, "{}", res.trim())?;
    }
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

fn enum_winrm(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== WINRM LISTENERS")?;
    let script = r#"
        $listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue
        if ($listeners) {
            foreach ($l in $listeners) {
                "Address: $($l.Address) | Transport: $($l.Transport) | Port: $($l.Port)"
            }
        } else {
            "No WinRM listeners found or WinRM is not configured."
        }
    "#;
    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", script])
        .output()?;
    let result = String::from_utf8_lossy(&output.stdout);
    writeln!(out, "{}", result.trim())?;
    Ok(())
}

// Enumerate Local Admins and Privileged Accounts
fn enum_local_admins(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== LOCAL ADMINS & PRIVILEGED ACCOUNTS")?;
    let script = r#"
        $privilegedGroups = @("Administrators", "Remote Management Users", "Remote Desktop Users")
        foreach ($group in $privilegedGroups) {
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            if ($members) {
                "Group: $group"
                foreach ($m in $members) {
                    # Filter for Local accounts (ignoring ActiveDirectory source if possible)
                    if ($m.PrincipalSource -eq 'Local') {
                        "  - $($m.Name) ($($m.ObjectClass))"
                    }
                }
            }
        }
    "#;
    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", script])
        .output()?;
    let result = String::from_utf8_lossy(&output.stdout);
    if result.trim().is_empty() {
        writeln!(out, "No local privileged accounts found (or script ran without sufficient permissions).")?;
    } else {
        writeln!(out, "{}", result.trim())?;
    }
    Ok(())
}