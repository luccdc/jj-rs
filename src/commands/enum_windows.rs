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

    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumSubcommands {
    /// Current network ports and listening services
    #[command(visible_alias("p"))]
    Ports(super::ports::Ports),
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        // Standard Enumeration
        enum_hostname(&mut ob)?;
        enum_ports(&mut ob, super::ports::Ports::default())?; // Added back
        
        // Security & Environment
        //enum_defender_status(&mut ob)?;
        enum_wsl_docker(&mut ob)?;
        
        // Web & Services
        enum_iis_sites(&mut ob)?;
        enum_python_sites(&mut ob)?;
        enum_ftp_sites(&mut ob)?;
        
        // Persistence & Files
        enum_startup_items(&mut ob)?;
        enum_system32_unsigned(&mut ob, self.detailed)?;

        Ok(())
    }
}

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

fn enum_iis_sites(out: &mut impl PagerOutput) -> eyre::Result<()> {
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
                    scan_web_files(out, path)?;
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

fn scan_web_files(out: &mut impl PagerOutput, root: &str) -> eyre::Result<()> {
    // 1. Clean the path (remove quotes or trailing spaces from PowerShell/appcmd)
    let clean_root = root.trim_matches(|c| c == '\"' || c == ' ');
    
    if !std::path::Path::new(clean_root).exists() {
        return Ok(());
    }

    writeln!(out, "Scanning directory: {}", clean_root)?;

    // List of common web shell extensions
    let danger_exts = ["php", "aspx", "asp", "jsp", "jspx", "cfm", "ashx", "asax", "html"];
    // List of common web shell names/keywords
    let danger_names = ["shell", "pony", "b374k", "c99", "r57", "cmd", "backdoor", "tunnel"];

    for entry in WalkDir::new(clean_root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            if danger_exts.contains(&ext_lower.as_str()) {
                let name_lower = path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();

                // Check if filename contains any dangerous keywords
                let is_sus = danger_names.iter().any(|&word| name_lower.contains(word));

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