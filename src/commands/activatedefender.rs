use base64::prelude::*;
use colored::*;
use std::io::Write;

use crate::utils::pager::{self, PagerOutput};

/// Harden Windows Defender, Firewall, and security registry settings
#[derive(clap::Parser, Clone, Debug, Default)]
pub struct ShieldsUp {
    /// Check permissions, existence, and ownership of Defender and Firewall registry keys
    #[arg(short = 'c', long)]
    pub checkperms: bool,
}

impl super::Command for ShieldsUp {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        if self.checkperms {
            check_registry_permissions(&mut ob)?;
        } else {
            activate_shields_up(&mut ob)?;
        }

        Ok(())
    }
}

/// Check permissions, existence, and ownership of Defender and Firewall registry paths
fn check_registry_permissions(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== REGISTRY PERMISSIONS & INTEGRITY AUDIT (SHIELDS UP)")?;

    let script = r#"
        $targetPaths = @(
            # Windows Defender Antivirus
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Description = "Core Antivirus Policy" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Description = "Real-Time Protection Policy" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Description = "Malware Protection Engine Policy" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Description = "Defender Reporting Policy" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet"; Description = "Cloud Protection (SpyNet) Policy" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"; Description = "Defender Policy Manager" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Description = "Windows Defender Core Engine" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Description = "Engine Real-Time Protection" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"; Description = "Windows Defender Antivirus Service" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc"; Description = "Network Inspection Service" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"; Description = "Defender for Endpoint Service" },
            @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService"; Description = "Security Health Service" },

            # Windows Defender Firewall
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc"; Description = "Windows Defender Firewall Service" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"; Description = "Firewall / SharedAccess Driver Service" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"; Description = "Firewall Standard/Private Profile" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"; Description = "Firewall Domain Profile" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"; Description = "Firewall Public Profile" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"; Description = "Firewall GPO Root Policy" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"; Description = "Firewall GPO Standard Profile" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Description = "Firewall GPO Domain Profile" },
            @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"; Description = "Firewall GPO Public Profile" },

            # System Security & Update Policies
            @{ Category = "System Security & Update Policies"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Description = "UAC & Token Filter Policy" },
            @{ Category = "System Security & Update Policies"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Description = "Windows Update Policy" }
        )

        $trustedOwners = @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "NT SERVICE\TrustedInstaller")

        foreach ($item in $targetPaths) {
            $cat = $item.Category
            $p = $item.Path
            $desc = $item.Description
            
            if (Test-Path $p) {
                try {
                    $acl = Get-Acl $p -ErrorAction Stop
                    $owner = $acl.Owner
                    
                    # Check owner validity
                    $isOwnerTrusted = $false
                    foreach ($to in $trustedOwners) {
                        if ($owner -like "*$to*" -or $owner -eq $to) {
                            $isOwnerTrusted = $true
                            break
                        }
                    }
                    if (-not $isOwnerTrusted) {
                        if ($owner -match "(?i)Administrators$" -or $owner -match "(?i)SYSTEM$") {
                            $isOwnerTrusted = $true
                        }
                    }
                    
                    # Check for Deny rules
                    $denyRules = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })
                    $denyDetails = ($denyRules | ForEach-Object { "$($_.IdentityReference):$($_.RegistryRights)" }) -join "; "
                    
                    # Check for Admin / SYSTEM Allow rules
                    $adminAllows = @($acl.Access | Where-Object { 
                        $_.AccessControlType -eq "Allow" -and 
                        ($_.IdentityReference -match "Administrators" -or $_.IdentityReference -match "SYSTEM")
                    })
                    
                    $hasWrite = $false
                    foreach ($ar in $adminAllows) {
                        $rights = $ar.RegistryRights.ToString()
                        if ($rights -match "FullControl" -or $rights -match "SetValue" -or $rights -match "WriteKey") {
                            $hasWrite = $true
                            break
                        }
                    }
                    
                    # Test direct write access
                    $canWrite = $false
                    try {
                        $subPath = $p -replace '^(HKLM:\\|HKLM:)', ''
                        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                        if ($regKey) {
                            $canWrite = $true
                            $regKey.Close()
                        }
                    } catch {
                        $canWrite = $false
                    }
                    
                    # Tamper-protected keys (Windows Defender Core Engine) have SYSTEM as FullControl and Admins as ReadKey by default
                    $isCoreEngine = ($p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender" -or $p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")
                    $accessOk = if ($isCoreEngine) {
                        ($isOwnerTrusted) -and ($denyRules.Count -eq 0)
                    } else {
                        ($canWrite -or $hasWrite) -and ($denyRules.Count -eq 0)
                    }
                    
                    # Check for known security disablement values
                    $badValues = @()
                    $vals = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    if ($vals) {
                        if ($vals.DisableAntiSpyware -eq 1) { $badValues += "DisableAntiSpyware=1" }
                        if ($vals.DisableAntiVirus -eq 1) { $badValues += "DisableAntiVirus=1" }
                        if ($vals.DisableRealtimeMonitoring -eq 1) { $badValues += "DisableRealtimeMonitoring=1" }
                        if ($vals.DisableBehaviorMonitoring -eq 1) { $badValues += "DisableBehaviorMonitoring=1" }
                        if ($vals.DisableOnAccessProtection -eq 1) { $badValues += "DisableOnAccessProtection=1" }
                        if ($vals.DisableIOAVProtection -eq 1) { $badValues += "DisableIOAVProtection=1" }
                        if ($vals.DisableScriptScanning -eq 1) { $badValues += "DisableScriptScanning=1" }
                        if ($vals.DisableBlockAtFirstSeen -eq 1) { $badValues += "DisableBlockAtFirstSeen=1" }
                        if ($vals.EnableFirewall -eq 0) { $badValues += "EnableFirewall=0" }
                        if ($vals.Start -eq 4) { $badValues += "Start=4 (Disabled)" }
                        if ($vals.EnableLUA -eq 0) { $badValues += "EnableLUA=0 (UAC Disabled)" }
                    }
                    $badValStr = $badValues -join ", "
                    
                    $isHealthy = $isOwnerTrusted -and $accessOk -and ($denyRules.Count -eq 0) -and ($badValues.Count -eq 0)
                    
                    Write-Output "STATUS_EXISTS: $cat|$p|$desc|$owner|$isOwnerTrusted|$($denyRules.Count)|$denyDetails|$accessOk|$canWrite|$badValStr|$isHealthy"
                } catch {
                    Write-Output "STATUS_DENIED: $cat|$p|$desc|$($_.Exception.Message)"
                }
            } else {
                # Check parent
                $parent = Split-Path $p -Parent
                $parentExists = Test-Path $parent
                $parentOwner = "NONE"
                $parentCanWrite = $false
                if ($parentExists) {
                    try {
                        $pAcl = Get-Acl $parent -ErrorAction SilentlyContinue
                        if ($pAcl) { $parentOwner = $pAcl.Owner }
                        $subParent = $parent -replace '^(HKLM:\\|HKLM:)', ''
                        $pk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subParent, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                        if ($pk) { $parentCanWrite = $true; $pk.Close() }
                    } catch {
                        $parentOwner = "ACCESS_DENIED"
                    }
                }
                Write-Output "STATUS_MISSING: $cat|$p|$desc|$parent|$parentExists|$parentOwner|$parentCanWrite"
            }
        }
    "#;

    let encoded_cmd = encode_command_utf16(script);
    let output = std::process::Command::new("powershell.exe")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded_cmd,
        ])
        .output()?;

    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    let mut current_category = String::new();
    let mut green_count = 0;
    let mut yellow_count = 0;

    for line in trimmed.lines() {
        let line = line.trim();
        if line.starts_with("STATUS_EXISTS:") {
            let data = line.replace("STATUS_EXISTS:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 11 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let owner = parts[3].trim();
                let is_trusted = parts[4].trim().eq_ignore_ascii_case("true");
                let deny_count: usize = parts[5].trim().parse().unwrap_or(0);
                let deny_details = parts[6].trim();
                let _access_ok = parts[7].trim().eq_ignore_ascii_case("true");
                let can_write = parts[8].trim().eq_ignore_ascii_case("true");
                let bad_values = parts[9].trim();
                let is_healthy = parts[10].trim().eq_ignore_ascii_case("true");

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                if is_healthy {
                    green_count += 1;
                    writeln!(out, "{}", format!("  [+] {} [{}]", path, desc).green())?;
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      Owner: {} [OK] | Admin Access: OK | Deny Rules: None",
                            owner
                        )
                        .green()
                    )?;
                } else {
                    yellow_count += 1;
                    writeln!(
                        out,
                        "{}",
                        format!("  [!] {} [{}]", path, desc).yellow().bold()
                    )?;
                    if !is_trusted {
                        writeln!(
                            out,
                            "{}",
                            format!(
                                "      [!] Owner: {} (Improper Owner - Expected SYSTEM, Administrators, or TrustedInstaller)",
                                owner
                            )
                            .yellow()
                        )?;
                    } else {
                        writeln!(out, "{}", format!("      [+] Owner: {} [OK]", owner).green())?;
                    }

                    if deny_count > 0 {
                        writeln!(
                            out,
                            "{}",
                            format!("      [!] Deny Rules: {}", deny_details).yellow()
                        )?;
                    }

                    if !can_write && !path.contains("SOFTWARE\\Microsoft\\Windows Defender") {
                        writeln!(
                            out,
                            "{}",
                            "      [!] Admin Access: Cannot write / modify key!".yellow()
                        )?;
                    }

                    if !bad_values.is_empty() {
                        writeln!(
                            out,
                            "{}",
                            format!("      [!] Tampered Security Values: {}", bad_values).yellow()
                        )?;
                    }
                }
            }
        } else if line.starts_with("STATUS_DENIED:") {
            yellow_count += 1;
            let data = line.replace("STATUS_DENIED:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 4 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let err = parts[3].trim();

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                writeln!(
                    out,
                    "{}",
                    format!("  [!] {} [{}]", path, desc).yellow().bold()
                )?;
                writeln!(
                    out,
                    "{}",
                    "      [!] Access Denied: Administrator locked out from reading security descriptor!"
                        .yellow()
                )?;
                writeln!(out, "{}", format!("      [!] Error: {}", err).yellow())?;
            }
        } else if line.starts_with("STATUS_MISSING:") {
            yellow_count += 1;
            let data = line.replace("STATUS_MISSING:", "");
            let parts: Vec<&str> = data.split('|').collect();
            if parts.len() >= 7 {
                let cat = parts[0].trim();
                let path = parts[1].trim();
                let desc = parts[2].trim();
                let parent = parts[3].trim();
                let _parent_exists = parts[4].trim().eq_ignore_ascii_case("true");
                let parent_owner = parts[5].trim();
                let parent_can_write = parts[6].trim().eq_ignore_ascii_case("true");

                if cat != current_category {
                    current_category = cat.to_string();
                    writeln!(out, "\n[+] {}", current_category)?;
                }

                writeln!(out, "{}", format!("  [!] {} [{}]", path, desc).yellow())?;
                if !parent_can_write {
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      [!] Key does not exist & parent '{}' is blocked from writes (Owner: {})",
                            parent, parent_owner
                        )
                        .yellow()
                    )?;
                } else {
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      [!] Key does not exist (Parent '{}' is accessible)",
                            parent
                        )
                        .yellow()
                    )?;
                }
            }
        }
    }

    // Summary Section
    writeln!(out, "\n==== REGISTRY AUDIT SUMMARY")?;
    writeln!(
        out,
        "{}",
        format!("  Properly Owned & Accessible (Green): {}", green_count).green().bold()
    )?;
    if yellow_count == 0 {
        writeln!(
            out,
            "{}",
            "  Improperly Owned / Missing / Inaccessible (Yellow): 0".green()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            format!(
                "  Improperly Owned / Missing / Inaccessible (Yellow): {}",
                yellow_count
            )
            .yellow()
            .bold()
        )?;
    }

    Ok(())
}

/// Apply Shields Up security hardening for Defender and Firewall
fn activate_shields_up(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== ACTIVATING SHIELDS UP (WINDOWS DEFENDER & FIREWALL)")?;

    let script = r#"
        $ErrorActionPreference = 'Continue'
        $errors = @()

        # 1. Enable UAC & System Security Policies
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -ErrorAction Stop
        } catch { $errors += "System Policies: $($_.Exception.Message)" }

        # 2. Enable Security Health Service
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
            Start-Service -Name "SecurityHealthService" -ErrorAction SilentlyContinue
        } catch { $errors += "SecurityHealthService: $($_.Exception.Message)" }

        # 3. Enable Core Windows Defender Antivirus Service (WinDefend)
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        } catch { $errors += "WinDefend Service: $($_.Exception.Message)" }

        # 4. Enable Windows Defender Policies
        try {
            if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "Windows Defender" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -Type DWord -ErrorAction Stop

            if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "MpEngine" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1 -Type DWord -ErrorAction Stop

            if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 0 -Type DWord -ErrorAction Stop

            if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Reporting" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 0 -Type DWord -ErrorAction Stop

            if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "SpyNet" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "DisableBlockAtFirstSeen" -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpynetReporting" -Value 1 -Type DWord -ErrorAction Stop
        } catch { $errors += "Windows Defender Policies: $($_.Exception.Message)" }

        # 5. Enable Windows Defender Firewall
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
            Start-Service -Name "MpsSvc" -ErrorAction SilentlyContinue

            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        } catch { $errors += "Firewall Configuration: $($_.Exception.Message)" }

        # 6. Enable Windows Update
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord -ErrorAction Stop
        } catch { $errors += "Windows Update: $($_.Exception.Message)" }

        if ($errors.Count -gt 0) {
            Write-Output "ERRORS_DETECTED"
            foreach ($e in $errors) {
                Write-Output "ERROR: $e"
            }
        } else {
            Write-Output "SHIELDS_UP_SUCCESS"
        }
    "#;

    let encoded_cmd = encode_command_utf16(script);
    let output = std::process::Command::new("powershell.exe")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded_cmd,
        ])
        .output()?;

    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    if trimmed.contains("SHIELDS_UP_SUCCESS") {
        writeln!(
            out,
            "{}",
            "[+] Shields Up applied! Windows Defender, Firewall, and security policies are active."
                .green()
                .bold()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            "  [!] Shields Up encountered errors setting some registry properties:".red().bold()
        )?;
        for line in trimmed.lines() {
            let line = line.trim();
            if line.starts_with("ERROR:") {
                writeln!(out, "      {}", line.replace("ERROR:", "").trim().red())?;
            }
        }
        writeln!(
            out,
            "{}",
            "  [!] Permissions may be locked. Run 'jj shieldsup --checkperms' to inspect registry permissions."
                .yellow()
        )?;
    }

    Ok(())
}

fn encode_command_utf16(command: &str) -> String {
    let utf16_bytes = command
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>();
    BASE64_STANDARD.encode(&utf16_bytes)
}
