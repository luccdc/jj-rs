# Stage simulated threats on the Windows VM for interactive testing
Import-Module WebAdministration -ErrorAction SilentlyContinue

Write-Host "[*] Setting up simulated threats in IIS..." -ForegroundColor Cyan

# 1. Directory and payload files
New-Item -ItemType Directory -Path "C:\threat_test" -Force | Out-Null
Set-Content -Path "C:\threat_test\evil_module.dll" -Value "MZ_SIMULATED_BACKDOOR_MODULE"
Set-Content -Path "C:\threat_test\evil_filter.dll" -Value "MZ_SIMULATED_BACKDOOR_FILTER"
Set-Content -Path "C:\threat_test\evil_handler.exe" -Value "MZ_SIMULATED_HANDLER_PROCESSOR"
Set-Content -Path "C:\threat_test\index.html" -Value "<h1>Threat Test Site</h1>"

# 2. Privileged AppPool & Site (Administrator/LocalSystem)
if (-not (Test-Path "IIS:\AppPools\ThreatAdminPool")) {
    New-WebAppPool -Name "ThreatAdminPool" -Force | Out-Null
}
Set-ItemProperty "IIS:\AppPools\ThreatAdminPool" -Name "processModel.identityType" -Value "LocalSystem"

if (Get-Website -Name "ThreatTestSite" -ErrorAction SilentlyContinue) {
    Remove-Website -Name "ThreatTestSite" -ErrorAction SilentlyContinue
}
New-Website -Name "ThreatTestSite" -Port 8088 -PhysicalPath "C:\threat_test" -ApplicationPool "ThreatAdminPool" -Force | Out-Null

# Disable logging on ThreatTestSite to demonstrate logging disabled alert
Set-ItemProperty "IIS:\Sites\ThreatTestSite" -Name logfile.enabled -Value $false

# 3. Custom / Unsigned Native Module
if (-not (Get-WebGlobalModule -Name "TestEvilModule" -ErrorAction SilentlyContinue)) {
    New-WebGlobalModule -Name "TestEvilModule" -Image "C:\threat_test\evil_module.dll" -Force | Out-Null
}

# 4. Custom ISAPI Filter
try {
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/isapiFilters" -Name "." -Value @{name='TestEvilFilter';path='C:\threat_test\evil_filter.dll'} -Force | Out-Null
} catch {}

# 5. Custom Handler Mapping
try {
    New-WebHandler -Name "TestEvilHandler" -Path "*.threat" -Verb "*" -ScriptProcessor "C:\threat_test\evil_handler.exe" -Force | Out-Null
} catch {}

# 6. Subdirectory web.config with accessPolicy="Execute" and handler override
New-Item -ItemType Directory -Path "C:\inetpub\wwwroot\threat_sub" -Force | Out-Null
Set-Content -Path "C:\inetpub\wwwroot\threat_sub\web.config" -Value @"
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Execute, Script">
      <add name="SubEvilHandler" path="*.xyz" verb="*" modules="IsapiModule" scriptProcessor="C:\threat_test\evil_filter.dll" resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
"@

Write-Host "[+] Staged threats on VM! They will remain active for your testing." -ForegroundColor Green
