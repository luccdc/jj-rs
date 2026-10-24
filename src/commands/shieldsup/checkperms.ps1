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
