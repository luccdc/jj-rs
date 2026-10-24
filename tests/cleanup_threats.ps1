# Cleanup all simulated threats on the Windows VM
Import-Module WebAdministration -ErrorAction SilentlyContinue

Write-Host "[*] Cleaning up test artifacts from IIS..." -ForegroundColor Yellow

# Remove test site
if (Get-Website -Name "ThreatTestSite" -ErrorAction SilentlyContinue) {
    Remove-Website -Name "ThreatTestSite" -ErrorAction SilentlyContinue
}
if (Test-Path "IIS:\AppPools\ThreatAdminPool") {
    Remove-WebAppPool -Name "ThreatAdminPool" -ErrorAction SilentlyContinue
}

# Remove test handlers
Remove-WebHandler -Name "TestEvilHandler" -ErrorAction SilentlyContinue

# Remove test ISAPI filters
try {
    Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/isapiFilters" -Name "." -AtElement @{name='TestEvilFilter'} -ErrorAction SilentlyContinue
} catch {}

# Remove global module
if (Get-WebGlobalModule -Name "TestEvilModule" -ErrorAction SilentlyContinue) {
    Remove-WebGlobalModule -Name "TestEvilModule" -ErrorAction SilentlyContinue
}

# Re-enable Default Web Site logging if altered
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name logfile.enabled -Value $true -ErrorAction SilentlyContinue

# Remove test directories
Remove-Item -Path "C:\threat_test" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\inetpub\wwwroot\threat_sub" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[+] Cleanup completed. VM is restored to clean state." -ForegroundColor Green
