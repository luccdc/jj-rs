# tests/test_iis_threats.ps1
# End-to-End Threat Detection Test Suite for `jj enum iis-sites`

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " JJ-RS IIS THREAT DETECTION TEST SUITE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$candidatePaths = @(
    "C:\vagrant\out\jj.exe",
    "C:\vagrant\target\x86_64-pc-windows-gnu\debug\jj-rs.exe",
    "\\vboxsrv\vagrant\out\jj.exe",
    "\\vboxsrv\vagrant\target\x86_64-pc-windows-gnu\debug\jj-rs.exe"
)

$binaryPath = ""
foreach ($p in $candidatePaths) {
    if (Test-Path $p) {
        $binaryPath = $p
        break
    }
}

if ([string]::IsNullOrEmpty($binaryPath)) {
    Write-Error "Could not locate jj.exe or jj-rs.exe binary in out/ or target/"
    exit 1
}

Import-Module WebAdministration -ErrorAction SilentlyContinue

function Cleanup-TestArtifacts {
    Write-Host "`n[*] Cleaning up test artifacts..." -ForegroundColor Yellow
    
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
    
    Write-Host "[+] Cleanup completed." -ForegroundColor Green
}

# Ensure clean slate before starting
Cleanup-TestArtifacts

$testsPassed = 0
$totalTests = 8

try {
    Write-Host "`n[1/5] Setting up simulated threats..." -ForegroundColor Cyan

    # 1. Directory and payload files
    New-Item -ItemType Directory -Path "C:\threat_test" -Force | Out-Null
    Set-Content -Path "C:\threat_test\evil_module.dll" -Value "MZ_SIMULATED_BACKDOOR_MODULE"
    Set-Content -Path "C:\threat_test\evil_filter.dll" -Value "MZ_SIMULATED_BACKDOOR_FILTER"
    Set-Content -Path "C:\threat_test\evil_handler.exe" -Value "MZ_SIMULATED_HANDLER_PROCESSOR"
    Set-Content -Path "C:\threat_test\index.html" -Value "<h1>Threat Test Site</h1>"

    # 2. Privileged AppPool & Site (Administrator/LocalSystem)
    New-WebAppPool -Name "ThreatAdminPool" -Force | Out-Null
    Set-ItemProperty "IIS:\AppPools\ThreatAdminPool" -Name "processModel.identityType" -Value "LocalSystem"
    New-Website -Name "ThreatTestSite" -Port 8088 -PhysicalPath "C:\threat_test" -ApplicationPool "ThreatAdminPool" -Force | Out-Null
    # Disable logging on ThreatTestSite to test logging disabled check
    Set-ItemProperty "IIS:\Sites\ThreatTestSite" -Name logfile.enabled -Value $false

    # 3. Custom / Unsigned Native Module
    New-WebGlobalModule -Name "TestEvilModule" -Image "C:\threat_test\evil_module.dll" -Force | Out-Null

    # 4. Custom ISAPI Filter
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/isapiFilters" -Name "." -Value @{name='TestEvilFilter';path='C:\threat_test\evil_filter.dll'} -Force | Out-Null

    # 5. Custom Handler Mapping
    New-WebHandler -Name "TestEvilHandler" -Path "*.threat" -Verb "*" -ScriptProcessor "C:\threat_test\evil_handler.exe" -Force | Out-Null

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

    Write-Host "[+] All threat scenarios staged successfully." -ForegroundColor Green

    # Run jj-rs enum iis-sites
    Write-Host "`n[2/5] Executing 'jj-rs.exe enum iis-sites'..." -ForegroundColor Cyan
    $output = & $binaryPath enum iis-sites | Out-String
    Write-Host $output

    Write-Host "`n[3/5] Asserting threat detections..." -ForegroundColor Cyan

    function Assert-Detection($name, $condition, $failureMsg) {
        if ($condition) {
            Write-Host "  [PASS] $name" -ForegroundColor Green
            $script:testsPassed++
        } else {
            Write-Host "  [FAIL] ${name} - $failureMsg" -ForegroundColor Red
        }
    }

    # Test 1: Privileged AppPool
    Assert-Detection "Privileged AppPool (LocalSystem / Administrator)" `
        ($output -match "RUNNING AS ADMINISTRATOR: LocalSystem") `
        "Expected alert 'RUNNING AS ADMINISTRATOR: LocalSystem' not found"

    # Test 2: Logging Disabled alert
    Assert-Detection "Disabled Logging Alert" `
        ($output -match "LOGGING DISABLED for site 'ThreatTestSite'") `
        "Expected alert 'LOGGING DISABLED for site ThreatTestSite' not found"

    # Test 3: Custom IIS Module backdoor
    Assert-Detection "Custom / Suspicious Native Module" `
        ($output -match "CUSTOM / SUSPICIOUS IIS MODULE: TestEvilModule") `
        "Expected module backdoor alert for 'TestEvilModule' not found"

    # Test 4: Suspicious ISAPI Filter
    Assert-Detection "Suspicious ISAPI Filter" `
        ($output -match "SUSPICIOUS ISAPI FILTER: TestEvilFilter") `
        "Expected ISAPI filter alert for 'TestEvilFilter' not found"

    # Test 5: Suspicious Handler Mapping
    Assert-Detection "Suspicious Handler Mapping" `
        ($output -match "SUSPICIOUS HANDLER MAPPING.*TestEvilHandler") `
        "Expected handler alert for 'TestEvilHandler' not found"

    # Test 6: Subdirectory web.config tampering
    Assert-Detection "Subdirectory web.config Backdoor" `
        ($output -match "SUSPICIOUS SUBDIRECTORY web.config:.*threat_sub") `
        "Expected alert for subdirectory web.config not found"

    # Test 7: WinRM IIS Extension
    Assert-Detection "WinRM IIS Extension Check" `
        ($output -match "WINRM IIS EXTENSION") `
        "Expected section 'WINRM IIS EXTENSION' not found"

    # Run with --printlog to test logging path listing
    Write-Host "`n[4/5] Testing '--printlog' flag..." -ForegroundColor Cyan
    $logOutput = & $binaryPath enum iis-sites --printlog | Out-String
    if ($logOutput -match "Log Directory:") {
        Write-Host "  [PASS] --printlog lists active log directory and files" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "  [FAIL] --printlog did not display log directory" -ForegroundColor Red
    }

    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host " TEST RESULTS: $testsPassed / $totalTests PASSED" -ForegroundColor $(if ($testsPassed -eq $totalTests) { "Green" } else { "Red" })
    Write-Host "====================================================" -ForegroundColor Cyan

    if ($testsPassed -ne $totalTests) {
        exit 1
    }
} finally {
    Write-Host "`n[5/5] Teardown & Cleanup..." -ForegroundColor Cyan
    Cleanup-TestArtifacts
}
