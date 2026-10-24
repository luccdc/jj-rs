$ErrorActionPreference = 'Continue'

# Enable privileges if possible (SeTakeOwnershipPrivilege, SeRestorePrivilege, SeBackupPrivilege)
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
        # Fallback to Set-Acl
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
        # Fallback via Get-Acl / Set-Acl
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

$auditBadCount = 0
$fixedKeyCount = 0
$errors = @()

# PHASE 1: Audit & Permission Remediation
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
        # Ensure parent path exists and is writable
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
        $issueStr = $issues -join "; "
        Write-Output "AUDIT_ISSUE: $cat|$p|$desc|$issueStr"

        # Remediate permissions unless core engine with active tamper protection
        if (-not $isCoreEngine) {
            $fixes = Repair-KeyPermissions -KeyPath $p
            if ($fixes.Count -gt 0) {
                $fixedKeyCount++
                $fixStr = $fixes -join ", "
                Write-Output "REPAIRED_PERMS: $p|$fixStr"
            }
        }
    } else {
        Write-Output "AUDIT_CLEAN: $cat|$p|$desc"
    }
}

# PHASE 2: Apply Hardened Values & Remove Malicious Overrides
Write-Output "PHASE_APPLY_SETTINGS"

# 1. System Security & UAC Policies
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -ErrorAction Stop
    Write-Output "SETTING_APPLIED: UAC EnableLUA=1, LocalAccountTokenFilterPolicy=0"
} catch { $errors += "System Policies: $($_.Exception.Message)" }

# 2. SecurityHealthService
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "SecurityHealthService" -ErrorAction SilentlyContinue
    Write-Output "SETTING_APPLIED: SecurityHealthService Start=2 (Automatic)"
} catch { $errors += "SecurityHealthService: $($_.Exception.Message)" }

# 3. Core Windows Defender Antivirus Service (WinDefend)
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\WinDefend" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    Write-Output "SETTING_APPLIED: WinDefend Start=2 (Automatic)"
} catch { $errors += "WinDefend Service: $($_.Exception.Message)" }

# 4. Windows Defender GPO Policies
try {
    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "Windows Defender" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\Software\Policies\Microsoft\Windows Defender" | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -Type DWord -ErrorAction Stop

    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "MpEngine" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1 -Type DWord -ErrorAction Stop

    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 0 -Type DWord -ErrorAction Stop

    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Reporting" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 0 -Type DWord -ErrorAction Stop

    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "SpyNet" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "DisableBlockAtFirstSeen" -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpynetReporting" -Value 1 -Type DWord -ErrorAction Stop

    Write-Output "SETTING_APPLIED: Windows Defender Antivirus Policies & Real-Time Monitoring enforced"
} catch { $errors += "Windows Defender Policies: $($_.Exception.Message)" }

# 5. Windows Defender Firewall Service & Policies
try {
    Repair-KeyPermissions -KeyPath "HKLM:\System\CurrentControlSet\Services\MpsSvc" | Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "MpsSvc" -ErrorAction SilentlyContinue

    Repair-KeyPermissions -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
    Start-Service -Name "SharedAccess" -ErrorAction SilentlyContinue

    # Service driver profiles
    $serviceProfiles = @("StandardProfile", "DomainProfile", "PublicProfile")
    foreach ($sp in $serviceProfiles) {
        $pKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$sp"
        if (Test-Path $pKey) {
            Repair-KeyPermissions -KeyPath $pKey | Out-Null
            Set-ItemProperty -Path $pKey -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
    }

    # GPO profiles
    foreach ($gp in $serviceProfiles) {
        $gKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$gp"
        if (-not (Test-Path $gKey)) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name $gp -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if (Test-Path $gKey) {
            Repair-KeyPermissions -KeyPath $gKey | Out-Null
            Set-ItemProperty -Path $gKey -Name "EnableFirewall" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
    }

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    Write-Output "SETTING_APPLIED: Windows Firewall Service & Profiles (Domain, Private, Public) enforced"
} catch { $errors += "Firewall Configuration: $($_.Exception.Message)" }

# 6. Windows Update AU Policy
try {
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force -ErrorAction Stop | Out-Null
    }
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force -ErrorAction Stop | Out-Null
    }
    Repair-KeyPermissions -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord -ErrorAction Stop
    Write-Output "SETTING_APPLIED: Windows Update AU Policy enforced"
} catch { $errors += "Windows Update: $($_.Exception.Message)" }

# PHASE 3: Service Status Verification
$servicesToCheck = @("WinDefend", "MpsSvc", "SecurityHealthService")
foreach ($svc in $servicesToCheck) {
    try {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Write-Output "SERVICE_STATE: $svc|$($s.Status)"
        } else {
            Write-Output "SERVICE_STATE: $svc|NOT_FOUND"
        }
    } catch {
        Write-Output "SERVICE_STATE: $svc|UNKNOWN"
    }
}

if ($errors.Count -gt 0) {
    foreach ($err in $errors) {
        Write-Output "ERROR: $err"
    }
}

Write-Output "YOLO_DONE: $($targetPaths.Count)|$auditBadCount|$fixedKeyCount|$($errors.Count)"
