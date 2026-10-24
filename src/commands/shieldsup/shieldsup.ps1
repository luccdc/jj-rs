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
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows" -Force -ErrorAction Stop | Out-Null
    }
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force -ErrorAction Stop | Out-Null
    }
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
