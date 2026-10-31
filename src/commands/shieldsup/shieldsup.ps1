[CmdletBinding()]
param(
    [switch]$Yolo = $false
)

$ErrorActionPreference = 'Continue'
$isYolo = $Yolo.IsPresent -or ($env:JJ_YOLO -eq '1')

# Enable privileges if in YOLO mode
if ($isYolo) {
    $definition = @"
using System;
using System.Runtime.InteropServices;

public class PrivilegeUtil {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref long lpLuid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const int TOKEN_QUERY = 0x0008;
    public const int SE_PRIVILEGE_ENABLED = 0x00000002;

    public static void EnablePrivileges() {
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken)) return;
        try {
            string[] privs = new string[] { "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeSecurityPrivilege" };
            foreach (string p in privs) {
                long luid = 0;
                if (LookupPrivilegeValue(null, p, ref luid)) {
                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                    AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                }
            }
        } catch {}
    }
}
"@
    try {
        if (-not ([System.Management.Automation.PSTypeName]'PrivilegeUtil').Type) {
            Add-Type -TypeDefinition $definition -ErrorAction SilentlyContinue
        }
        [PrivilegeUtil]::EnablePrivileges()
    } catch {}
}

$targetPaths = @(
    # Windows Defender Antivirus
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Description = "Core Antivirus Policy"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Description = "Real-Time Protection Policy"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Description = "Malware Protection Engine Policy"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Description = "Defender Reporting Policy"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet"; Description = "Cloud Protection (SpyNet) Policy"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"; Description = "Defender Policy Manager"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Description = "Windows Defender Core Engine"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Description = "Engine Real-Time Protection"; Service = "" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"; Description = "Windows Defender Antivirus Service"; Service = "WinDefend" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc"; Description = "Network Inspection Service"; Service = "WdNisSvc" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"; Description = "Defender for Endpoint Service"; Service = "Sense" },
    @{ Category = "Windows Defender Antivirus"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService"; Description = "Security Health Service"; Service = "SecurityHealthService" },

    # Windows Defender Firewall
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc"; Description = "Windows Defender Firewall Service"; Service = "MpsSvc" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"; Description = "Firewall / SharedAccess Driver Service"; Service = "SharedAccess" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"; Description = "Firewall Standard/Private Profile"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"; Description = "Firewall Domain Profile"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"; Description = "Firewall Public Profile"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"; Description = "Firewall GPO Root Policy"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"; Description = "Firewall GPO Standard Profile"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Description = "Firewall GPO Domain Profile"; Service = "" },
    @{ Category = "Windows Defender Firewall"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"; Description = "Firewall GPO Public Profile"; Service = "" },

    # System Security & Update Policies
    @{ Category = "System Security & Update Policies"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Description = "UAC & Token Filter Policy"; Service = "" },
    @{ Category = "System Security & Update Policies"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Description = "Windows Update Policy"; Service = "" }
)

$trustedOwners = @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "NT SERVICE\TrustedInstaller")
$adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
$systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")

function Repair-KeyPermissions {
    param([string]$KeyPath)

    $repaired = @()
    $subPath = $KeyPath -replace '^(HKLM:\\|HKLM:)', ''

    # 1. Take ownership if needed
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        if ($regKey) {
            $acl = $regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
            $acl.SetOwner($adminAccount)
            $regKey.SetAccessControl($acl)
            $regKey.Close()
            $repaired += "Ownership set to BUILTIN\Administrators"
        }
    } catch {
        try {
            $acl = Get-Acl $KeyPath -ErrorAction Stop
            $acl.SetOwner($adminAccount)
            Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction SilentlyContinue
            $repaired += "Ownership set to BUILTIN\Administrators (Set-Acl)"
        } catch {}
    }

    # 2. Open with ChangePermissions right to remove Deny rules and add Allow FullControl
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($regKey) {
            $acl = $regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
            
            # Remove all Deny rules
            $rules = $acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $denyCount = 0
            foreach ($r in $rules) {
                if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                    $acl.RemoveAccessRuleSpecific($r) | Out-Null
                    $denyCount++
                }
            }
            if ($denyCount -gt 0) {
                $repaired += "Removed $denyCount Deny rule(s)"
            }

            # Grant FullControl to BUILTIN\Administrators and NT AUTHORITY\SYSTEM
            $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $adminAccount,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $systemAccount,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.ResetAccessRule($adminRule)
            $acl.AddAccessRule($systemRule)

            $regKey.SetAccessControl($acl)
            $regKey.Close()
            $repaired += "Granted FullControl to Administrators & SYSTEM"
        }
    } catch {
        try {
            $acl = Get-Acl $KeyPath -ErrorAction Stop
            $rules = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })
            foreach ($r in $rules) {
                $acl.RemoveAccessRule($r) | Out-Null
            }
            $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.ResetAccessRule($adminRule)
            $acl.AddAccessRule($systemRule)
            Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction SilentlyContinue
            $repaired += "ACL repaired via Set-Acl"
        } catch {}
    }

    return $repaired
}

# ==============================================================================
# DEFAULT MODE: AUDIT & GIVE REPORT OF CHANGED/MISSING KEYS & PERMISSIONS
# ==============================================================================
if (-not $isYolo) {
    Write-Output "`n==== REGISTRY PERMISSIONS & INTEGRITY AUDIT (SHIELDS UP)"

    $currentCategory = ""
    $greenCount = 0
    $yellowCount = 0

    foreach ($item in $targetPaths) {
        $cat = $item.Category
        $p = $item.Path
        $desc = $item.Description

        if ($cat -ne $currentCategory) {
            $currentCategory = $cat
            Write-Output "`n[+] $currentCategory"
        }

        if (Test-Path $p) {
            try {
                $acl = Get-Acl $p -ErrorAction Stop
                $owner = $acl.Owner

                # Check owner
                $isOwnerTrusted = $false
                foreach ($to in $trustedOwners) {
                    if ($owner -like "*$to*" -or $owner -eq $to) { $isOwnerTrusted = $true; break }
                }
                if (-not $isOwnerTrusted) {
                    if ($owner -match "(?i)Administrators$" -or $owner -match "(?i)SYSTEM$") { $isOwnerTrusted = $true }
                }

                # Check Deny rules
                $denyRules = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })
                $denyDetails = ($denyRules | ForEach-Object { "$($_.IdentityReference):$($_.RegistryRights)" }) -join "; "

                # Check write access
                $canWrite = $false
                try {
                    $subPath = $p -replace '^(HKLM:\\|HKLM:)', ''
                    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                    if ($regKey) { $canWrite = $true; $regKey.Close() }
                } catch { $canWrite = $false }

                $isCoreEngine = ($p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender" -or $p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")
                $accessOk = if ($isCoreEngine) { $isOwnerTrusted -and ($denyRules.Count -eq 0) } else { $canWrite -and ($denyRules.Count -eq 0) }

                # Check sabotage/tampered values
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

                $isHealthy = $isOwnerTrusted -and $accessOk -and ($denyRules.Count -eq 0) -and ($badValues.Count -eq 0)

                if ($isHealthy) {
                    $greenCount++
                    Write-Output "  [+] $p [$desc]"
                    Write-Output "      Owner: $owner [OK] | Admin Access: OK | Deny Rules: None"
                } else {
                    $yellowCount++
                    Write-Output "  [!] $p [$desc]"
                    if (-not $isOwnerTrusted) {
                        Write-Output "      [!] Owner: $owner (Improper Owner - Expected SYSTEM, Administrators, or TrustedInstaller)"
                    } else {
                        Write-Output "      [+] Owner: $owner [OK]"
                    }
                    if ($denyRules.Count -gt 0) {
                        Write-Output "      [!] Deny Rules: $denyDetails"
                    }
                    if (-not $accessOk) {
                        Write-Output "      [!] Admin Access: Cannot write / modify key!"
                    }
                    if ($badValues.Count -gt 0) {
                        $badValStr = $badValues -join ", "
                        Write-Output "      [!] Tampered Security Values: $badValStr"
                    }
                }
            } catch {
                $yellowCount++
                Write-Output "  [!] $p [$desc]"
                Write-Output "      [!] Access Denied reading ACL: $($_.Exception.Message)"
            }
        } else {
            $yellowCount++
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

            Write-Output "  [!] $p [$desc]"
            if (-not $parentExists) {
                Write-Output "      [!] Key and parent do not exist ($parent missing)"
            } elseif ($parentCanWrite) {
                Write-Output "      [!] Key does not exist (Parent '$parent' is accessible)"
            } else {
                Write-Output "      [!] Key does not exist & parent '$parent' is blocked from writes (Owner: $parentOwner)"
            }
        }
    }

    Write-Output "`n==== REGISTRY AUDIT SUMMARY"
    Write-Output "  Properly Owned & Accessible (Green): $greenCount"
    Write-Output "  Improperly Owned / Missing / Inaccessible (Yellow): $yellowCount"

    if ($yellowCount -gt 0) {
        Write-Output "`n  [!] Issues detected! Run 'jj shieldsup --yolo' (or '.\shieldsup.ps1 -Yolo') to repair permissions, remove Deny rules, and enforce security settings."
    } else {
        Write-Output "`n  [+] All audited Defender and Firewall registry keys are properly owned and accessible."
    }

    exit 0
}

# ==============================================================================
# YOLO MODE: AUDIT, REMEDIATE PERMISSIONS/DENY RULES, AND ENFORCE SECURITY
# ==============================================================================
Write-Output "`n==== YOLO MODE: AUDITING & REMEDIATING WINDOWS DEFENDER & FIREWALL ===="

$auditBadCount = 0
$fixedKeyCount = 0
$errors = @()
$auditIssuesByCategory = @{}
$repairedLog = @()

# PHASE 1: Audit & Identify Issues
foreach ($item in $targetPaths) {
    $cat = $item.Category
    $p = $item.Path
    $desc = $item.Description
    $isCoreEngine = ($p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender" -or $p -eq "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")

    $needsRepair = $false
    $issues = @()

    if (Test-Path $p) {
        try {
            $acl = Get-Acl $p -ErrorAction Stop
            $owner = $acl.Owner

            $isOwnerTrusted = $false
            foreach ($to in $trustedOwners) {
                if ($owner -like "*$to*" -or $owner -eq $to) { $isOwnerTrusted = $true; break }
            }
            if (-not $isOwnerTrusted) {
                if ($owner -match "(?i)Administrators$" -or $owner -match "(?i)SYSTEM$") { $isOwnerTrusted = $true }
            }
            if (-not $isOwnerTrusted) {
                $needsRepair = $true
                $issues += "Improper owner ($owner)"
            }

            $denyRules = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })
            if ($denyRules.Count -gt 0) {
                $needsRepair = $true
                $issues += "Explicit Deny ACEs ($($denyRules.Count))"
            }

            # Test write access
            $subPath = $p -replace '^(HKLM:\\|HKLM:)', ''
            $canWrite = $false
            try {
                $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                if ($k) { $canWrite = $true; $k.Close() }
            } catch { $canWrite = $false }

            if (-not $canWrite -and -not $isCoreEngine) {
                $needsRepair = $true
                $issues += "Admin write access blocked"
            }

            # Check sabotage values
            $vals = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($vals) {
                if ($vals.DisableAntiSpyware -eq 1) { $issues += "DisableAntiSpyware=1"; $needsRepair = $true }
                if ($vals.DisableAntiVirus -eq 1) { $issues += "DisableAntiVirus=1"; $needsRepair = $true }
                if ($vals.DisableRealtimeMonitoring -eq 1) { $issues += "DisableRealtimeMonitoring=1"; $needsRepair = $true }
                if ($vals.DisableBehaviorMonitoring -eq 1) { $issues += "DisableBehaviorMonitoring=1"; $needsRepair = $true }
                if ($vals.DisableIOAVProtection -eq 1) { $issues += "DisableIOAVProtection=1"; $needsRepair = $true }
                if ($vals.DisableOnAccessProtection -eq 1) { $issues += "DisableOnAccessProtection=1"; $needsRepair = $true }
                if ($vals.DisableScriptScanning -eq 1) { $issues += "DisableScriptScanning=1"; $needsRepair = $true }
                if ($vals.DisableBlockAtFirstSeen -eq 1) { $issues += "DisableBlockAtFirstSeen=1"; $needsRepair = $true }
                if ($vals.EnableFirewall -eq 0) { $issues += "EnableFirewall=0"; $needsRepair = $true }
                if ($vals.Start -eq 4) { $issues += "Service Disabled (Start=4)"; $needsRepair = $true }
                if ($vals.EnableLUA -eq 0) { $issues += "UAC Disabled (EnableLUA=0)"; $needsRepair = $true }
            }
        } catch {
            $needsRepair = $true
            $issues += "Access Denied reading ACL: $($_.Exception.Message)"
        }
    } else {
        $needsRepair = $true
        $issues += "Key missing"
        # Ensure parent exists and is writable
        $parent = Split-Path $p -Parent
        if (-not (Test-Path $parent)) {
            $grandParent = Split-Path $parent -Parent
            $parentName = Split-Path $parent -Leaf
            if (Test-Path $grandParent) {
                Repair-KeyPermissions -KeyPath $grandParent | Out-Null
                New-Item -Path $grandParent -Name $parentName -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Repair-KeyPermissions -KeyPath $parent | Out-Null
        $keyName = Split-Path $p -Leaf
        New-Item -Path $parent -Name $keyName -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if ($needsRepair) {
        $auditBadCount++
        if (-not $auditIssuesByCategory.ContainsKey($cat)) {
            $auditIssuesByCategory[$cat] = @()
        }
        $auditIssuesByCategory[$cat] += @{ Path = $p; Description = $desc; Issue = ($issues -join "; ") }

        if (-not $isCoreEngine) {
            $fixes = Repair-KeyPermissions -KeyPath $p
            if ($fixes.Count -gt 0) {
                $fixedKeyCount++
                $repairedLog += @{ Path = $p; Fixes = ($fixes -join ", ") }
            }
        }
    }
}

# Output Phase 1 Findings
Write-Output "`n[*] Phase 1: Registry Audit Findings"
if ($auditIssuesByCategory.Count -eq 0) {
    Write-Output "  [+] All target registry keys exist with clean permissions and trusted ownership."
} else {
    foreach ($cat in $auditIssuesByCategory.Keys) {
        Write-Output "`n  [Category] $cat"
        foreach ($issue in $auditIssuesByCategory[$cat]) {
            Write-Output "    [!] $($issue.Path) [$($issue.Description)]"
            Write-Output "        Issue: $($issue.Issue)"
        }
    }
}

# Output Phase 2 Findings
Write-Output "`n[*] Phase 2: Permission & Ownership Remediation"
if ($repairedLog.Count -eq 0) {
    Write-Output "  [+] No permission remediation was required; administrators already had write access."
} else {
    foreach ($r in $repairedLog) {
        Write-Output "  [+] Fixed: $($r.Path)"
        Write-Output "      Actions: $($r.Fixes)"
    }
}

# PHASE 3: Apply Hardened Values & Remove Malicious Overrides
Write-Output "`n[*] Phase 3: Applied Hardening Policies & Settings"

# 1. System Security & UAC Policies
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -ErrorAction Stop
    Write-Output "  [+] UAC EnableLUA=1, LocalAccountTokenFilterPolicy=0"
} catch { $errors += "System Policies: $($_.Exception.Message)" }

# 2. SecurityHealthService
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "SecurityHealthService" -ErrorAction SilentlyContinue
    Write-Output "  [+] SecurityHealthService Start=2 (Automatic)"
} catch { $errors += "SecurityHealthService: $($_.Exception.Message)" }

# 3. Windows Defender Antivirus Service (WinDefend)
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\WinDefend" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
} catch { $errors += "WinDefend Service: $($_.Exception.Message)" }

# 4. Windows Defender Policies
try {
    $defRoot = "HKLM:\Software\Policies\Microsoft\Windows Defender"
    Repair-KeyPermissions -KeyPath $defRoot | Out-Null
    Set-ItemProperty -Path $defRoot -Name "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $defRoot -Name "DisableAntiVirus" -Value 0 -Type DWord -ErrorAction Stop

    $mpEngine = "$defRoot\MpEngine"
    if (-not (Test-Path $mpEngine)) { New-Item -Path $defRoot -Name "MpEngine" -Force -ErrorAction SilentlyContinue | Out-Null }
    Repair-KeyPermissions -KeyPath $mpEngine | Out-Null
    Set-ItemProperty -Path $mpEngine -Name "MpEnablePus" -Value 1 -Type DWord -ErrorAction Stop

    $rtProt = "$defRoot\Real-Time Protection"
    if (-not (Test-Path $rtProt)) { New-Item -Path $defRoot -Name "Real-Time Protection" -Force -ErrorAction SilentlyContinue | Out-Null }
    Repair-KeyPermissions -KeyPath $rtProt | Out-Null
    Set-ItemProperty -Path $rtProt -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $rtProt -Name "DisableIOAVProtection" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $rtProt -Name "DisableOnAccessProtection" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $rtProt -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $rtProt -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $rtProt -Name "DisableScriptScanning" -Value 0 -Type DWord -ErrorAction Stop

    $reporting = "$defRoot\Reporting"
    if (-not (Test-Path $reporting)) { New-Item -Path $defRoot -Name "Reporting" -Force -ErrorAction SilentlyContinue | Out-Null }
    Repair-KeyPermissions -KeyPath $reporting | Out-Null
    Set-ItemProperty -Path $reporting -Name "DisableEnhancedNotifications" -Value 0 -Type DWord -ErrorAction Stop

    $spyNet = "$defRoot\SpyNet"
    if (-not (Test-Path $spyNet)) { New-Item -Path $defRoot -Name "SpyNet" -Force -ErrorAction SilentlyContinue | Out-Null }
    Repair-KeyPermissions -KeyPath $spyNet | Out-Null
    Set-ItemProperty -Path $spyNet -Name "DisableBlockAtFirstSeen" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $spyNet -Name "SpynetReporting" -Value 1 -Type DWord -ErrorAction Stop

    Write-Output "  [+] Windows Defender Antivirus Policies & Real-Time Monitoring enforced"
} catch { $errors += "Windows Defender Policies: $($_.Exception.Message)" }

# 5. Windows Defender Firewall
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\MpsSvc" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "MpsSvc" -ErrorAction SilentlyContinue

    $fwBase = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    Repair-KeyPermissions -KeyPath "$fwBase\StandardProfile" | Out-Null
    Set-ItemProperty -Path "$fwBase\StandardProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop

    Repair-KeyPermissions -KeyPath "$fwBase\DomainProfile" | Out-Null
    Set-ItemProperty -Path "$fwBase\DomainProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop

    Repair-KeyPermissions -KeyPath "$fwBase\PublicProfile" | Out-Null
    Set-ItemProperty -Path "$fwBase\PublicProfile" -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction Stop

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    Write-Output "  [+] Windows Firewall Service & Profiles (Domain, Private, Public) enforced"
} catch { $errors += "Firewall Configuration: $($_.Exception.Message)" }

# 6. Windows Update AU Policy
try {
    $wuRoot = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $wuRoot)) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force -ErrorAction SilentlyContinue | Out-Null }
    $wuAU = "$wuRoot\AU"
    if (-not (Test-Path $wuAU)) { New-Item -Path $wuRoot -Name "AU" -Force -ErrorAction SilentlyContinue | Out-Null }
    Repair-KeyPermissions -KeyPath $wuAU | Out-Null
    Set-ItemProperty -Path $wuAU -Name "NoAutoUpdate" -Value 0 -Type DWord -ErrorAction Stop
    Write-Output "  [+] Windows Update AU Policy enforced"
} catch { $errors += "Windows Update Policy: $($_.Exception.Message)" }

# PHASE 4: Security Services Verification
Write-Output "`n[*] Phase 4: Security Services Verification"
$servicesToCheck = @("WinDefend", "MpsSvc", "SecurityHealthService")
foreach ($svcName in $servicesToCheck) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Start-Service -Name $svcName -ErrorAction SilentlyContinue
                $svc.Refresh()
            }
            Write-Output "  [+] Service '$svcName': $($svc.Status)"
        } else {
            Write-Output "  [!] Service '$svcName': Not Found"
        }
    } catch {
        Write-Output "  [!] Service '$svcName': $($_.Exception.Message)"
    }
}

if ($errors.Count -gt 0) {
    Write-Output "`n  [!] Errors encountered during execution:"
    foreach ($err in $errors) {
        Write-Output "      [!] $err"
    }
}

# PHASE 5: Summary
Write-Output "`n==== YOLO REMEDIATION SUMMARY"
Write-Output "  Total Keys Audited: $($targetPaths.Count)"
Write-Output "  Issues Detected:    $auditBadCount"
Write-Output "  Keys Remediated:    $fixedKeyCount"
Write-Output "  Errors:             $($errors.Count)"

if ($errors.Count -eq 0 -and $auditBadCount -gt 0) {
    Write-Output "`n  [+] All detected issues were remediated and systems hardened successfully!"
} elseif ($auditBadCount -eq 0) {
    Write-Output "`n  [+] System was already clean; hardening configuration confirmed."
} else {
    Write-Output "`n  [!] Completed with warnings. Inspect the errors above."
}
