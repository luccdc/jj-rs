use base64::prelude::*;

/// Fix registry keys to ensure Active Directory can run
#[derive(clap::Parser, Clone, Debug)]
pub struct ShieldsUp;

impl super::Command for ShieldsUp {
    fn execute(self) -> eyre::Result<()> {
        let command = r#"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
            
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 2 -Type DWord
            
            New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "Windows Defender" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord
            
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -Type DWord
            
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "MpEngine" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1 -Type DWord
            
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 0 -Type DWord
            
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Reporting" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 0 -Type DWord
            
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "SpyNet" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "DisableBlockAtFirstSeen" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpynetReporting" -Value 1 -Type DWord
            
            
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
            
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
        "#;

        let command = command
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>();

        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &BASE64_STANDARD.encode(command),
            ])
            .spawn()?
            .wait()?;

        Ok(())
    }
}
