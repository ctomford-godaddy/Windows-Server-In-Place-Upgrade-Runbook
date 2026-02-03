# Windows Server In-Place Upgrade Runbook
## 2016 → 2019/2022/2025 Enterprise Guide

**Original Guide:** Andrew Griffiths  
**Enhanced By:** Chad Tomford  
**Team:** org-gpe-ms-common-services  
**Last Updated:** January 2025

---

## Table of Contents
1. [Overview and Upgrade Paths](#overview-and-upgrade-paths)
2. [Prerequisites Checklist](#prerequisites-checklist)
3. [Phase 1 - Pre-Flight Validation](#phase-1---pre-flight-validation)
4. [Phase 2 - Pre-Upgrade Preparation](#phase-2---pre-upgrade-preparation)
5. [Phase 3 - Execute Upgrade](#phase-3---execute-upgrade)
6. [Phase 4 - Post-Upgrade Validation](#phase-4---post-upgrade-validation)
7. [Phase 5 - Agent and Service Restoration](#phase-5---agent-and-service-restoration)
8. [Rollback Procedure](#rollback-procedure)
9. [Known Issues and Lessons Learned](#known-issues-and-lessons-learned)
10. [Troubleshooting and Common Issues](#troubleshooting-and-common-issues)
11. [Appendix - Quick Reference](#appendix---quick-reference)

---

## Overview and Upgrade Paths

### Supported Direct Upgrade Paths
| Source | Target | Direct? | Notes |
|--------|--------|---------|-------|
| 2016 | 2019 | ✅ Yes | Recommended intermediate step |
| 2016 | 2022 | ✅ Yes | Supported but less tested |
| 2016 | 2025 | ✅ Yes | Supported, thorough testing recommended |
| 2019 | 2022 | ✅ Yes | Clean path |
| 2019 | 2025 | ✅ Yes | Supported |
| 2022 | 2025 | ✅ Yes | Cleanest path |

### Critical Requirements
- **Edition must match**: Standard → Standard, Datacenter → Datacenter
- **Architecture must match**: 64-bit only for Server 2016+
- **Minimum 20GB free disk space** on system drive
- **No pending reboots** before starting

### ISO Repository
```
https://woerepo.mcs.int.gdcorp.tools/installers/iso/
├── w2k19-s-64.iso    # Windows Server 2019 Standard
├── w21h2-s-64.iso    # Windows Server 2022 Standard  
└── w24h2-s-64.iso    # Windows Server 2025 Standard
```
> **Access Issues?** Contact #gpd-mscommon-services in Slack

### Expected Timeline
| System Type | Duration | Notes |
|-------------|----------|-------|
| Vanilla/minimal roles | 40-50 min | Base estimate |
| IIS/Web servers | 50-70 min | Additional config migration |
| Domain Controllers | 60-90 min | **Not recommended for in-place** |
| SQL Server installed | 60-80 min | Verify SQL compatibility first |
| Heavy third-party software | 60-90 min | Agent reinstalls may be needed |

---

## Prerequisites Checklist

### Access & Permissions
- [ ] Admin privileges on target VM
- [ ] Access to OpenStack for backup verification
- [ ] Access to NCM/HAProxy if applicable
- [ ] ServiceNow access for maintenance window

### Stakeholder Communication
- [ ] Identify all application owners
- [ ] Schedule maintenance window (recommend 2-hour buffer)
- [ ] Send notification to stakeholders with:
  - Start time
  - Expected duration (40-60 min + validation)
  - Rollback criteria
  - Contact information

### Infrastructure Preparation
- [ ] Verify recent backup exists in OpenStack
  - Docs: https://docs.openstack.int.gd3p.tools/features/dr_backups.html
  - Request via #openstack_bots if needed
- [ ] Check NCM/HAProxy membership - remove from pool if applicable
- [ ] Place VM in maintenance mode in ServiceNow
- [ ] Document current IP configuration (for rollback validation)

---

## Phase 1 - Pre-Flight Validation

Run this script to validate the system is ready for upgrade. **All blockers must be resolved before proceeding.**

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pre-flight validation for Windows Server in-place upgrade
.DESCRIPTION
    Checks for blockers and warnings before attempting upgrade
.NOTES
    Run this BEFORE starting the upgrade process
#>

[CmdletBinding()]
param(
    [switch]$AutoRemediate  # Attempt to fix non-critical issues
)

$ErrorActionPreference = 'Continue'
$blockers = @()
$warnings = @()

Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
Write-Host "  WINDOWS SERVER IN-PLACE UPGRADE PRE-FLIGHT CHECK" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  Target: $env:COMPUTERNAME"
Write-Host "  Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("=" * 60) -ForegroundColor Cyan

#region Current System Info
Write-Host "`n[INFO] Current System Configuration" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$edition = (Get-WindowsEdition -Online).Edition

Write-Host "  OS:        $($os.Caption)"
Write-Host "  Build:     $($os.BuildNumber)"
Write-Host "  Edition:   $edition"
Write-Host "  Install:   $($os.InstallDate)"

# Determine required ISO
$isoNeeded = switch -Regex ($edition) {
    'Standard'   { 'Standard ISO (w2k19-s-64.iso, w21h2-s-64.iso, or w24h2-s-64.iso)' }
    'Datacenter' { 'Datacenter ISO - contact team for location' }
    default      { "Unknown edition: $edition - VERIFY MANUALLY" }
}
Write-Host "  ISO Type:  $isoNeeded" -ForegroundColor Cyan
#endregion

#region Check 1: Pending Reboot
Write-Host "`n[CHECK 1] Pending Reboot Status" -ForegroundColor Yellow
$rebootReasons = @()

if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA SilentlyContinue) {
    $rebootReasons += "PendingFileRenameOperations"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $rebootReasons += "WindowsUpdate RebootRequired"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $rebootReasons += "CBS RebootPending"
}
if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name JoinDomain -EA SilentlyContinue) {
    $rebootReasons += "Pending domain join"
}

if ($rebootReasons) {
    $blockers += "Pending reboot detected: $($rebootReasons -join ', ')"
    Write-Host "  ✗ BLOCKER: Reboot pending - $($rebootReasons -join ', ')" -ForegroundColor Red
} else {
    Write-Host "  ✓ No pending reboot" -ForegroundColor Green
}
#endregion

#region Check 2: Disk Space
Write-Host "`n[CHECK 2] Disk Space" -ForegroundColor Yellow
$systemDrive = Get-PSDrive C
$freeGB = [math]::Round($systemDrive.Free / 1GB, 2)
$totalGB = [math]::Round(($systemDrive.Used + $systemDrive.Free) / 1GB, 2)

Write-Host "  C: Drive - $freeGB GB free of $totalGB GB total"

if ($freeGB -lt 15) {
    $blockers += "Insufficient disk space: $freeGB GB free (need 20GB minimum)"
    Write-Host "  ✗ BLOCKER: Need at least 20GB free" -ForegroundColor Red
} elseif ($freeGB -lt 20) {
    $warnings += "Disk space marginal: $freeGB GB (20GB recommended)"
    Write-Host "  ⚠ WARNING: Recommend 20GB+ free" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ Sufficient disk space" -ForegroundColor Green
}
#endregion

#region Check 3: Domain Connectivity
Write-Host "`n[CHECK 3] Domain Connectivity" -ForegroundColor Yellow
try {
    $secureChannel = Test-ComputerSecureChannel -ErrorAction Stop
    if ($secureChannel) {
        Write-Host "  ✓ Domain secure channel healthy" -ForegroundColor Green
        
        # Additional DC connectivity test
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "  ✓ Connected to domain: $($domain.Name)" -ForegroundColor Green
    }
} catch {
    $warnings += "Domain secure channel issue: $_"
    Write-Host "  ⚠ WARNING: Secure channel test failed - $($_.Exception.Message)" -ForegroundColor Yellow
}
#endregion

#region Check 4: SCCM Client Status
Write-Host "`n[CHECK 4] SCCM Client Status" -ForegroundColor Yellow
$ccmService = Get-Service ccmexec -EA SilentlyContinue

if ($ccmService) {
    Write-Host "  Service Status: $($ccmService.Status)"
    
    try {
        $smsClient = Get-CimInstance -Namespace root\ccm -ClassName SMS_Client -EA Stop
        $smsAuthority = Get-CimInstance -Namespace root\ccm -ClassName SMS_Authority -EA Stop
        
        Write-Host "  Client Version: $($smsClient.ClientVersion)"
        Write-Host "  Site Code:      $($smsAuthority.Name -replace 'SMS:','')"
        Write-Host "  ✓ SCCM client configured" -ForegroundColor Green
        
        # Note for post-upgrade
        Write-Host "  ℹ NOTE: SCCM client may need reinstallation post-upgrade" -ForegroundColor Cyan
    } catch {
        $warnings += "SCCM client present but WMI query failed"
        Write-Host "  ⚠ WARNING: Could not query SCCM WMI" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ℹ SCCM client not installed" -ForegroundColor Gray
}
#endregion

#region Check 5: Windows Roles
Write-Host "`n[CHECK 5] Installed Roles Analysis" -ForegroundColor Yellow
$installedRoles = Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' }

# Roles that may complicate upgrades
$problematicRoles = @(
    'AD-Domain-Services',      # DCs should not use in-place upgrade
    'WSUS',                    # Complex, may have issues
    'RDS-RD-Server',           # RDS can be tricky
    'Hyper-V',                 # Nested virtualization concerns
    'ADFS-Federation',         # Certificate dependencies
    'NPAS'                     # Network Policy Server
)

$foundProblematic = $installedRoles | Where-Object { $_.Name -in $problematicRoles }

Write-Host "  Installed Roles:"
$installedRoles | ForEach-Object { Write-Host "    - $($_.DisplayName)" }

if ($foundProblematic) {
    foreach ($role in $foundProblematic) {
        if ($role.Name -eq 'AD-Domain-Services') {
            $blockers += "Domain Controller detected - in-place upgrade NOT recommended for DCs"
            Write-Host "  ✗ BLOCKER: DC detected - use migration instead" -ForegroundColor Red
        } else {
            $warnings += "Role '$($role.DisplayName)' may require additional validation"
            Write-Host "  ⚠ WARNING: $($role.DisplayName) - verify post-upgrade" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  ✓ No problematic roles detected" -ForegroundColor Green
}
#endregion

#region Check 6: Third-Party Services
Write-Host "`n[CHECK 6] Third-Party Agents & Services" -ForegroundColor Yellow

$agentsToCheck = @(
    @{Name='Site24x7'; Service='Site24x7 Windows Agent'; Action='Verify post-upgrade'},
    @{Name='Qualys'; Service='QualysAgent'; Action='Check compatibility with target OS'},
    @{Name='Splunk'; Service='SplunkForwarder'; Action='Verify post-upgrade'},
    @{Name='CrowdStrike'; Service='CSFalconService'; Action='May need reinstall'},
    @{Name='Tanium'; Service='Tanium Client'; Action='Verify post-upgrade'}
)

foreach ($agent in $agentsToCheck) {
    $svc = Get-Service $agent.Service -EA SilentlyContinue
    if ($svc) {
        Write-Host "  Found: $($agent.Name) ($($svc.Status))" -ForegroundColor Cyan
        Write-Host "    Action: $($agent.Action)" -ForegroundColor Gray
    }
}
#endregion

#region Check 7: IIS Configuration
Write-Host "`n[CHECK 7] IIS Configuration" -ForegroundColor Yellow
$iisService = Get-Service W3SVC -EA SilentlyContinue

if ($iisService) {
    Write-Host "  IIS Detected - Status: $($iisService.Status)" -ForegroundColor Cyan
    
    try {
        Import-Module WebAdministration -EA Stop
        $sites = Get-Website
        $bindings = Get-WebBinding
        
        Write-Host "  Sites: $($sites.Count)"
        Write-Host "  Bindings: $($bindings.Count)"
        
        # Check for SSL bindings
        $sslBindings = $bindings | Where-Object { $_.protocol -eq 'https' }
        if ($sslBindings) {
            Write-Host "  SSL Bindings: $($sslBindings.Count)" -ForegroundColor Cyan
            Write-Host "    ℹ NOTE: Export bindings before upgrade" -ForegroundColor Cyan
        }
        
        $warnings += "IIS installed - backup bindings and verify post-upgrade"
    } catch {
        Write-Host "  ⚠ Could not query IIS configuration" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ℹ IIS not installed" -ForegroundColor Gray
}
#endregion

#region Check 8: Component Store Health
Write-Host "`n[CHECK 8] Component Store Health" -ForegroundColor Yellow
Write-Host "  Running DISM health check (this may take a moment)..."

$dismResult = & dism /Online /Cleanup-Image /CheckHealth 2>&1
if ($dismResult -match 'No component store corruption detected') {
    Write-Host "  ✓ Component store healthy" -ForegroundColor Green
} elseif ($dismResult -match 'repairable') {
    $warnings += "Component store has repairable corruption"
    Write-Host "  ⚠ WARNING: Corruption detected but repairable" -ForegroundColor Yellow
    Write-Host "    Run: DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Gray
} else {
    Write-Host "  ℹ Health check complete" -ForegroundColor Gray
}
#endregion

#region Check 9: Network Configuration
Write-Host "`n[CHECK 9] Network Configuration" -ForegroundColor Yellow
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
$ipConfigs = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }

Write-Host "  Active Adapters:"
foreach ($adapter in $adapters) {
    $ip = ($ipConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex }).IPv4Address.IPAddress
    Write-Host "    $($adapter.Name): $ip ($($adapter.LinkSpeed))"
}

# DNS check
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }
Write-Host "  DNS Servers: $(($dns.ServerAddresses | Select-Object -Unique) -join ', ')"
#endregion

#region Check 10: Scheduled Tasks with Stored Credentials
Write-Host "`n[CHECK 10] Scheduled Tasks Analysis" -ForegroundColor Yellow
$customTasks = Get-ScheduledTask | Where-Object { 
    $_.TaskPath -notmatch '^\\Microsoft' -and 
    $_.State -ne 'Disabled' 
}

if ($customTasks) {
    Write-Host "  Custom scheduled tasks found: $($customTasks.Count)"
    $customTasks | ForEach-Object {
        $principal = $_.Principal.UserId
        Write-Host "    - $($_.TaskName) [runs as: $principal]" -ForegroundColor Gray
    }
    Write-Host "  ℹ NOTE: Tasks with stored credentials may need re-authentication post-upgrade" -ForegroundColor Cyan
} else {
    Write-Host "  ✓ No custom scheduled tasks" -ForegroundColor Green
}
#endregion

#region Summary
Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
Write-Host "  PRE-FLIGHT SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

if ($blockers) {
    Write-Host "`n  BLOCKERS ($($blockers.Count)) - Must resolve before upgrade:" -ForegroundColor Red
    $blockers | ForEach-Object { Write-Host "    ✗ $_" -ForegroundColor Red }
}

if ($warnings) {
    Write-Host "`n  WARNINGS ($($warnings.Count)) - Review before proceeding:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "    ⚠ $_" -ForegroundColor Yellow }
}

if (-not $blockers -and -not $warnings) {
    Write-Host "`n  ✓ ALL CHECKS PASSED - System ready for upgrade" -ForegroundColor Green
} elseif (-not $blockers) {
    Write-Host "`n  ✓ No blockers found - Review warnings and proceed with caution" -ForegroundColor Yellow
} else {
    Write-Host "`n  ✗ BLOCKERS FOUND - Do not proceed until resolved" -ForegroundColor Red
}

Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
#endregion

# Return results for automation
[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Edition = $edition
    CurrentBuild = $os.BuildNumber
    FreeSpaceGB = $freeGB
    Blockers = $blockers
    Warnings = $warnings
    ReadyForUpgrade = ($blockers.Count -eq 0)
}
```

---

## Phase 2 - Pre-Upgrade Preparation

### 2.1 Create Local Admin Fallback

Always create/verify a local admin account before upgrade. Domain authentication may fail post-upgrade.

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Create or reset the local 'cactus' admin account for upgrade fallback
#>

$accountName = 'cactus'

# Generate secure password
$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
$password = -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

# Ensure complexity requirements
$password = $password.Substring(0,12) + 'Aa1!'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# Check if account exists
$localUser = Get-LocalUser -Name $accountName -EA SilentlyContinue

if ($localUser) {
    # Reset password
    Set-LocalUser -Name $accountName -Password $securePassword
    Enable-LocalUser -Name $accountName
    Write-Host "Reset password for existing '$accountName' account" -ForegroundColor Green
} else {
    # Create account
    New-LocalUser -Name $accountName -Password $securePassword -PasswordNeverExpires -Description "Upgrade fallback account"
    Add-LocalGroupMember -Group "Administrators" -Member $accountName
    Write-Host "Created new '$accountName' admin account" -ForegroundColor Green
}

# Verify authentication works
$cred = New-Object PSCredential($accountName, $securePassword)
try {
    Start-Process cmd -Credential $cred -WindowStyle Hidden -ErrorAction Stop
    Write-Host "✓ Authentication verified successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Authentication failed - check password" -ForegroundColor Red
}

# Display credentials (copy these!)
Write-Host ("`n" + ("=" * 50)) -ForegroundColor Cyan
Write-Host "  LOCAL ADMIN CREDENTIALS - SAVE THESE" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan
Write-Host "  Username: .\$accountName"
Write-Host "  Password: $password"
Write-Host ("=" * 50) -ForegroundColor Cyan
Write-Host "`nStore these securely before proceeding!`n" -ForegroundColor Yellow
Write-Host "Store in Vault: https://vault.secrets.int.gd3p.tools/ui/vault/secrets/gpe-ms-common-services_prod_kv-v2/kv/list/dev-migration/windows/`n" -ForegroundColor Gray
```

### 2.2 Backup Critical Configurations

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Export critical configurations before upgrade
#>

$backupPath = "C:\UpgradeBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

Write-Host "Backing up configurations to: $backupPath" -ForegroundColor Cyan

# 1. IIS Configuration (if installed)
if (Get-Service W3SVC -EA SilentlyContinue) {
    Write-Host "  Exporting IIS configuration..."
    
    # Full IIS backup
    $iisBackup = Join-Path $backupPath "IIS"
    New-Item -Path $iisBackup -ItemType Directory -Force | Out-Null
    
    & "$env:windir\system32\inetsrv\appcmd.exe" add backup "PreUpgrade_$(Get-Date -Format 'yyyyMMdd')"
    
    # Export bindings separately for easy reference
    Import-Module WebAdministration -EA SilentlyContinue
    Get-WebBinding | Export-Clixml (Join-Path $iisBackup "WebBindings.xml")
    Get-Website | Export-Clixml (Join-Path $iisBackup "Websites.xml")
    Get-WebApplication | Export-Clixml (Join-Path $iisBackup "Applications.xml")
    
    Write-Host "  ✓ IIS configuration exported" -ForegroundColor Green
}

# 2. Scheduled Tasks
Write-Host "  Exporting scheduled tasks..."
$tasksPath = Join-Path $backupPath "ScheduledTasks"
New-Item -Path $tasksPath -ItemType Directory -Force | Out-Null

Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft' } | ForEach-Object {
    $taskName = $_.TaskName -replace '[\\/:*?"<>|]', '_'
    Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | 
        Out-File (Join-Path $tasksPath "$taskName.xml")
}
Write-Host "  ✓ Scheduled tasks exported" -ForegroundColor Green

# 3. Network Configuration
Write-Host "  Exporting network configuration..."
$netPath = Join-Path $backupPath "Network"
New-Item -Path $netPath -ItemType Directory -Force | Out-Null

Get-NetIPConfiguration | Export-Clixml (Join-Path $netPath "IPConfiguration.xml")
Get-NetAdapter | Export-Clixml (Join-Path $netPath "Adapters.xml")
Get-DnsClientServerAddress | Export-Clixml (Join-Path $netPath "DNS.xml")
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Export-Clixml (Join-Path $netPath "FirewallRules.xml")

# Also export as text for easy reading
ipconfig /all > (Join-Path $netPath "ipconfig.txt")
route print > (Join-Path $netPath "routes.txt")
netsh advfirewall show allprofiles > (Join-Path $netPath "firewall_profiles.txt")

Write-Host "  ✓ Network configuration exported" -ForegroundColor Green

# 4. Installed Software List
Write-Host "  Exporting installed software list..."
Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | 
    Export-Csv (Join-Path $backupPath "InstalledSoftware.csv") -NoTypeInformation
Write-Host "  ✓ Software list exported" -ForegroundColor Green

# 5. Services Configuration
Write-Host "  Exporting services configuration..."
Get-Service | Select-Object Name, DisplayName, Status, StartType | 
    Export-Csv (Join-Path $backupPath "Services.csv") -NoTypeInformation
Write-Host "  ✓ Services exported" -ForegroundColor Green

# 6. Local Users and Groups
Write-Host "  Exporting local users and groups..."
Get-LocalUser | Export-Clixml (Join-Path $backupPath "LocalUsers.xml")
Get-LocalGroup | ForEach-Object {
    [PSCustomObject]@{
        Group = $_.Name
        Members = (Get-LocalGroupMember $_.Name -EA SilentlyContinue).Name -join '; '
    }
} | Export-Csv (Join-Path $backupPath "LocalGroups.csv") -NoTypeInformation
Write-Host "  ✓ Local accounts exported" -ForegroundColor Green

# 7. SCCM Client Info (if installed)
if (Get-Service ccmexec -EA SilentlyContinue) {
    Write-Host "  Exporting SCCM client info..."
    $sccmPath = Join-Path $backupPath "SCCM"
    New-Item -Path $sccmPath -ItemType Directory -Force | Out-Null
    
    try {
        Get-CimInstance -Namespace root\ccm -ClassName SMS_Client | Export-Clixml (Join-Path $sccmPath "SMS_Client.xml")
        Get-CimInstance -Namespace root\ccm -ClassName SMS_Authority | Export-Clixml (Join-Path $sccmPath "SMS_Authority.xml")
        Write-Host "  ✓ SCCM info exported" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Could not export SCCM info" -ForegroundColor Yellow
    }
}

# Summary
Write-Host ("`n" + ("=" * 50)) -ForegroundColor Green
Write-Host "  BACKUP COMPLETE" -ForegroundColor Green
Write-Host "  Location: $backupPath" -ForegroundColor Green
Write-Host ("=" * 50) -ForegroundColor Green

Get-ChildItem $backupPath -Recurse | Measure-Object -Property Length -Sum | 
    ForEach-Object { Write-Host "  Total Size: $([math]::Round($_.Sum / 1KB, 2)) KB" }
```

### 2.3 Clean Up Component Store (Optional)

> **Note:** In enterprise environments with controlled Windows Update (WSUS/SCCM), these commands may fail with `0x800f081f` (source files not found). This is expected and does not block the upgrade. The in-place upgrade replaces the entire component store anyway.

```powershell
# Reduce upgrade time and potential issues by cleaning component store
Write-Host "Cleaning component store (this may take several minutes)..." -ForegroundColor Yellow

# Analyze first
Dism /Online /Cleanup-Image /AnalyzeComponentStore

# Attempt cleanup - may fail in enterprise environments, that's OK
Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠ Component cleanup failed (likely due to WSUS/no WU access) - proceeding anyway" -ForegroundColor Yellow
}

# Clear Windows Update cache
Stop-Service wuauserv -Force
Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -EA SilentlyContinue
Start-Service wuauserv

Write-Host "✓ Cleanup complete (or skipped)" -ForegroundColor Green
```

**If pre-flight reports component store corruption:**

- Corruption in cumulative update packages (e.g., KB5041773) cannot be repaired with RTM ISO
- The upgrade will proceed despite this corruption
- Post-upgrade, the component store will be fresh from the new OS

```powershell
# To see what's corrupted (informational only):
Select-String -Path C:\Windows\Logs\CBS\CBS.log -Pattern "CBS_E_STORE_CORRUPTION" | Select-Object -Last 10
```

---

## Phase 3 - Execute Upgrade

### 3.1 Upgrade Script (Production Version)

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server In-Place Upgrade - Production Script
.DESCRIPTION
    Downloads ISO, mounts, executes upgrade with full error handling
.PARAMETER TargetVersion
    Target Windows Server version: 2019, 2022, or 2025
.PARAMETER Quiet
    Run in quiet mode (no GUI). Remove for troubleshooting.
.EXAMPLE
    .\Invoke-WindowsUpgrade.ps1 -TargetVersion 2025
    .\Invoke-WindowsUpgrade.ps1 -TargetVersion 2019 -Quiet:$false
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('2019', '2022', '2025')]
    [string]$TargetVersion,
    
    [switch]$Quiet = $true
)

$ErrorActionPreference = 'Stop'

# ISO mapping
$isoMap = @{
    '2019' = 'w2k19-s-64.iso'
    '2022' = 'w21h2-s-64.iso'
    '2025' = 'w24h2-s-64.iso'
}

$baseUrl = 'https://woerepo.mcs.int.gdcorp.tools/installers/iso'
$isoFile = $isoMap[$TargetVersion]
$isoUrl = "$baseUrl/$isoFile"
$isoPath = "C:\Windows\Temp\$isoFile"
$logPath = "C:\Windows\Temp\UpgradeLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $(switch($Level) { 'ERROR' {'Red'} 'WARN' {'Yellow'} default {'White'} })
    Add-Content -Path $logPath -Value $logMessage
}

# Banner
Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
Write-Host "  WINDOWS SERVER IN-PLACE UPGRADE" -ForegroundColor Cyan
Write-Host "  Target: Windows Server $TargetVersion" -ForegroundColor Cyan
Write-Host "  Server: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Mode:   $(if($Quiet){'Quiet (Unattended)'}else{'Interactive'})" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

Write-Log "Starting upgrade process to Windows Server $TargetVersion"

#region Pre-Checks
Write-Log "Running pre-flight checks..."

# Check disk space
$freeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
if ($freeGB -lt 15) {
    Write-Log "Insufficient disk space: $freeGB GB (need 20GB)" -Level ERROR
    throw "Insufficient disk space"
}
Write-Log "Disk space OK: $freeGB GB free"

# Check pending reboot
$pendingReboot = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or
                 (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
if ($pendingReboot) {
    Write-Log "Pending reboot detected - cannot proceed" -Level ERROR
    throw "Pending reboot - please restart and try again"
}
Write-Log "No pending reboots"
#endregion

#region Download ISO
Write-Log "Downloading ISO from: $isoUrl"
Write-Host "`nDownloading ISO (this may take several minutes)..." -ForegroundColor Yellow

try {
    # Remove existing ISO if present
    if (Test-Path $isoPath) {
        Write-Log "Removing existing ISO file"
        Remove-Item $isoPath -Force
    }
    
    $dlStart = Get-Date
    Start-BitsTransfer -Source $isoUrl -Destination $isoPath -ErrorAction Stop
    $dlDuration = (Get-Date) - $dlStart
    
    # Verify download
    $isoSize = [math]::Round((Get-Item $isoPath).Length / 1GB, 2)
    if ($isoSize -lt 3) {
        throw "ISO appears incomplete: $isoSize GB (expected >4GB)"
    }
    
    Write-Log "Download complete: $isoSize GB in $([math]::Round($dlDuration.TotalMinutes, 1)) minutes"
} catch {
    Write-Log "ISO download failed: $_" -Level ERROR
    throw
}
#endregion

#region Mount ISO
Write-Log "Mounting ISO image..."

try {
    $mountResult = Mount-DiskImage -ImagePath $isoPath -PassThru
    Start-Sleep -Seconds 3  # Allow mount to complete
    
    # Get drive letter - more robust detection
    $diskImage = Get-DiskImage -ImagePath $isoPath
    $volume = Get-Volume | Where-Object { 
        $_.DriveType -eq 'CD-ROM' -and 
        $_.DriveLetter -and
        (Test-Path "$($_.DriveLetter):\setup.exe")
    } | Select-Object -First 1
    
    if (-not $volume) {
        # Fallback method
        $volume = Get-CimInstance Win32_Volume | Where-Object { 
            $_.DriveType -eq 5 -and $_.DriveLetter 
        } | Select-Object -First 1
    }
    
    if (-not $volume) {
        throw "Could not determine mounted ISO drive letter"
    }
    
    $driveLetter = $volume.DriveLetter
    if ($driveLetter -notmatch ':$') { $driveLetter += ':' }
    
    $setupPath = "$driveLetter\setup.exe"
    if (-not (Test-Path $setupPath)) {
        throw "setup.exe not found at $setupPath"
    }
    
    Write-Log "ISO mounted at $driveLetter"
} catch {
    Write-Log "Mount failed: $_" -Level ERROR
    Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
    throw
}
#endregion

#region Execute Upgrade
Write-Log "Starting Windows Setup..."
Write-Host ("`n" + ("=" * 60)) -ForegroundColor Yellow
Write-Host "  UPGRADE STARTING - DO NOT INTERRUPT" -ForegroundColor Yellow
Write-Host "  Expected duration: 40-60 minutes" -ForegroundColor Yellow
Write-Host "  Log file: C:\`$WINDOWS.~BT\Sources\Panther\setupact.log" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor Yellow

# Build arguments
$setupArgs = @(
    "/auto upgrade"
    "/dynamicupdate disable"
    "/compat IgnoreWarning"
    "/showoobe none"
    "/EULA accept"
    "/copylogs C:\Windows\Temp\UpgradeLogs"
)

if ($Quiet) {
    $setupArgs += "/quiet"
    $setupArgs += "/noreboot"
}

$argString = $setupArgs -join ' '
Write-Log "Setup arguments: $argString"

try {
    $upgradeStart = Get-Date
    $process = Start-Process -FilePath $setupPath -ArgumentList $argString -Wait -PassThru
    $upgradeDuration = (Get-Date) - $upgradeStart
    
    Write-Log "Setup completed with exit code: $($process.ExitCode)"
    Write-Log "Duration: $([math]::Round($upgradeDuration.TotalMinutes, 1)) minutes"
    
    # Interpret exit code
    switch ($process.ExitCode) {
        0       { Write-Log "SUCCESS: Upgrade completed successfully" }
        3010    { Write-Log "SUCCESS: Upgrade completed - reboot required" }
        -1047527529 { Write-Log "WARNING: Compatibility issues detected" -Level WARN }
        default { Write-Log "Setup exited with code: $($process.ExitCode)" -Level WARN }
    }
} catch {
    Write-Log "Setup execution failed: $_" -Level ERROR
    throw
} finally {
    # Always cleanup
    Write-Log "Cleaning up..."
    Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
    # Keep ISO for potential retry - remove manually after success
    # Remove-Item -Path $isoPath -Force -ErrorAction SilentlyContinue
}
#endregion

#region Final Instructions
Write-Host ("`n" + ("=" * 60)) -ForegroundColor Green
Write-Host "  UPGRADE PHASE COMPLETE" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host @"

  Next Steps:
  1. Reboot the server: Restart-Computer -Force
  2. After reboot, log in and run post-upgrade validation
  3. Verify SCCM client, monitoring agents, and applications
  4. Remove from maintenance mode in ServiceNow
  5. Re-add to load balancer pool if applicable
  
  Log file saved to: $logPath
  ISO retained at: $isoPath (delete after confirming success)

"@ -ForegroundColor White
#endregion
```

### 3.2 Monitoring Upgrade Progress

While the upgrade runs, monitor from another session:

```powershell
# Monitor upgrade progress (run from separate session)
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'

# Watch for setup.exe process
while ($true) {
    $setup = Get-Process setup -EA SilentlyContinue
    if ($setup) {
        $cpu = $setup.CPU
        $mem = [math]::Round($setup.WorkingSet64 / 1MB, 0)
        
        # Get last log entry
        $lastLog = if (Test-Path $logPath) { 
            Get-Content $logPath -Tail 1 -EA SilentlyContinue 
        } else { "Waiting for log..." }
        
        Clear-Host
        Write-Host "=== UPGRADE MONITOR ===" -ForegroundColor Cyan
        Write-Host "Time:    $(Get-Date -Format 'HH:mm:ss')"
        Write-Host "CPU:     $cpu seconds"
        Write-Host "Memory:  $mem MB"
        Write-Host "`nLast Log Entry:" -ForegroundColor Yellow
        Write-Host $lastLog
    } else {
        Write-Host "Setup.exe not running - upgrade may be complete or not started"
    }
    Start-Sleep -Seconds 10
}
```

---

## Phase 4 - Post-Upgrade Validation

Run this script after the server reboots to validate the upgrade succeeded.

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Post-upgrade validation script
.DESCRIPTION
    Validates system health after Windows Server in-place upgrade
#>

$ErrorActionPreference = 'Continue'
$issues = @()

Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
Write-Host "  POST-UPGRADE VALIDATION" -ForegroundColor Cyan
Write-Host "  Server: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

#region OS Verification
Write-Host "`n[CHECK] Operating System" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  Caption:  $($os.Caption)"
Write-Host "  Version:  $($os.Version)"
Write-Host "  Build:    $($os.BuildNumber)"

# Verify expected version
$expectedBuilds = @{
    '2019' = '17763'
    '2022' = '20348'
    '2025' = '26100'
}

$buildMatch = $expectedBuilds.Values -contains $os.BuildNumber
if ($buildMatch) {
    Write-Host "  ✓ OS version verified" -ForegroundColor Green
} else {
    $issues += "OS build $($os.BuildNumber) not in expected list"
    Write-Host "  ⚠ Verify OS version is correct" -ForegroundColor Yellow
}
#endregion

#region Domain Connectivity
Write-Host "`n[CHECK] Domain Connectivity" -ForegroundColor Yellow
try {
    $secureChannel = Test-ComputerSecureChannel
    if ($secureChannel) {
        Write-Host "  ✓ Domain secure channel healthy" -ForegroundColor Green
    } else {
        $issues += "Domain secure channel broken"
        Write-Host "  ✗ Secure channel broken - may need to rejoin domain" -ForegroundColor Red
    }
} catch {
    $issues += "Domain connectivity test failed: $_"
    Write-Host "  ✗ Domain test failed: $_" -ForegroundColor Red
}
#endregion

#region Critical Services
Write-Host "`n[CHECK] Critical Services" -ForegroundColor Yellow
$criticalServices = @(
    @{Name='W32Time'; Display='Windows Time'},
    @{Name='Netlogon'; Display='Net Logon'},
    @{Name='LanmanServer'; Display='Server'},
    @{Name='LanmanWorkstation'; Display='Workstation'},
    @{Name='EventLog'; Display='Event Log'},
    @{Name='DHCP'; Display='DHCP Client'},
    @{Name='Dnscache'; Display='DNS Client'}
)

foreach ($svc in $criticalServices) {
    $service = Get-Service $svc.Name -EA SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Write-Host "  ✓ $($svc.Display): Running" -ForegroundColor Green
        } else {
            $issues += "$($svc.Display) service is $($service.Status)"
            Write-Host "  ✗ $($svc.Display): $($service.Status)" -ForegroundColor Red
        }
    }
}
#endregion

#region Network Connectivity
Write-Host "`n[CHECK] Network Connectivity" -ForegroundColor Yellow
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

foreach ($adapter in $adapters) {
    $ip = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -EA SilentlyContinue).IPAddress
    Write-Host "  $($adapter.Name): $ip ($($adapter.LinkSpeed))"
}

# Test basic connectivity
$gatewayTest = Test-NetConnection -ComputerName (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop -WarningAction SilentlyContinue
if ($gatewayTest.PingSucceeded) {
    Write-Host "  ✓ Gateway reachable" -ForegroundColor Green
} else {
    $issues += "Default gateway not reachable"
    Write-Host "  ✗ Gateway not reachable" -ForegroundColor Red
}
#endregion

#region SCCM Client
Write-Host "`n[CHECK] SCCM Client" -ForegroundColor Yellow
$ccmService = Get-Service ccmexec -EA SilentlyContinue

if ($ccmService) {
    Write-Host "  Service Status: $($ccmService.Status)"
    
    if ($ccmService.Status -eq 'Running') {
        try {
            $smsClient = Get-CimInstance -Namespace root\ccm -ClassName SMS_Client -EA Stop
            $smsAuthority = Get-CimInstance -Namespace root\ccm -ClassName SMS_Authority -EA Stop
            $siteCode = $smsAuthority.Name -replace 'SMS:',''
            
            Write-Host "  Client Version: $($smsClient.ClientVersion)"
            Write-Host "  Site Code: $siteCode"
            Write-Host "  ✓ SCCM client operational" -ForegroundColor Green
        } catch {
            $issues += "SCCM client running but WMI unhealthy"
            Write-Host "  ⚠ SCCM WMI issue - may need reinstall" -ForegroundColor Yellow
        }
    } else {
        $issues += "SCCM client service not running"
        Write-Host "  ⚠ Service not running - attempting start..." -ForegroundColor Yellow
        Start-Service ccmexec -EA SilentlyContinue
    }
} else {
    Write-Host "  ℹ SCCM client not installed" -ForegroundColor Gray
}
#endregion

#region IIS (if applicable)
Write-Host "`n[CHECK] IIS Status" -ForegroundColor Yellow
$iisService = Get-Service W3SVC -EA SilentlyContinue

if ($iisService) {
    Write-Host "  W3SVC Status: $($iisService.Status)"
    
    if ($iisService.Status -eq 'Running') {
        try {
            Import-Module WebAdministration -EA Stop
            $sites = Get-Website
            
            foreach ($site in $sites) {
                $state = $site.State
                $stateColor = if ($state -eq 'Started') { 'Green' } else { 'Yellow' }
                Write-Host "  Site '$($site.Name)': $state" -ForegroundColor $stateColor
                
                if ($state -ne 'Started') {
                    $issues += "IIS site '$($site.Name)' is $state"
                }
            }
            
            # Check SSL bindings
            $sslBindings = Get-WebBinding -Protocol https
            if ($sslBindings) {
                Write-Host "  SSL Bindings: $($sslBindings.Count) configured"
            }
        } catch {
            Write-Host "  ⚠ Could not query IIS - Import-Module WebAdministration failed" -ForegroundColor Yellow
        }
    } else {
        $issues += "IIS service not running"
        Write-Host "  ✗ IIS not running" -ForegroundColor Red
    }
} else {
    Write-Host "  ℹ IIS not installed" -ForegroundColor Gray
}
#endregion

#region Scheduled Tasks
Write-Host "`n[CHECK] Scheduled Tasks" -ForegroundColor Yellow
$disabledTasks = Get-ScheduledTask | Where-Object { 
    $_.TaskPath -notmatch '^\\Microsoft' -and 
    $_.State -eq 'Disabled' 
}

if ($disabledTasks) {
    Write-Host "  ⚠ Disabled custom tasks found:" -ForegroundColor Yellow
    $disabledTasks | ForEach-Object { 
        Write-Host "    - $($_.TaskName)" -ForegroundColor Yellow
        $issues += "Scheduled task '$($_.TaskName)' is disabled"
    }
} else {
    Write-Host "  ✓ No unexpected disabled tasks" -ForegroundColor Green
}
#endregion

#region Event Log Errors
Write-Host "`n[CHECK] Recent Critical/Error Events (last hour)" -ForegroundColor Yellow
$recentErrors = Get-WinEvent -FilterHashtable @{
    LogName = 'System', 'Application'
    Level = 1, 2  # Critical, Error
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 10 -EA SilentlyContinue

if ($recentErrors) {
    Write-Host "  ⚠ Recent errors found:" -ForegroundColor Yellow
    $recentErrors | Select-Object -First 5 | ForEach-Object {
        Write-Host "    [$($_.LevelDisplayName)] $($_.ProviderName): $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))..." -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✓ No critical errors in last hour" -ForegroundColor Green
}
#endregion

#region Windows Update
Write-Host "`n[CHECK] Windows Update Status" -ForegroundColor Yellow
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates.Count
    
    Write-Host "  Pending updates: $pendingUpdates"
    if ($pendingUpdates -gt 0) {
        Write-Host "  ℹ Consider applying pending updates" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  ⚠ Could not check Windows Update status" -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
Write-Host "  VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

if ($issues) {
    Write-Host "`n  ISSUES FOUND ($($issues.Count)):" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "    ⚠ $_" -ForegroundColor Yellow }
    Write-Host "`n  Review issues above before removing from maintenance" -ForegroundColor Yellow
} else {
    Write-Host "`n  ✓ ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "  System appears healthy - proceed with final verification" -ForegroundColor Green
}

Write-Host "`n  Next Steps:" -ForegroundColor Cyan
Write-Host "    1. Review any issues above"
Write-Host "    2. Test application functionality"
Write-Host "    3. Verify monitoring agents (Site24x7, Qualys)"
Write-Host "    4. Remove from ServiceNow maintenance"
Write-Host "    5. Re-add to load balancer pool"
Write-Host "    6. Notify stakeholders of completion"
Write-Host "`n"
#endregion
```

---

## Phase 5 - Agent and Service Restoration

### 5.1 SCCM Client Reinstallation

If SCCM client is unhealthy post-upgrade:

```powershell
# SCCM Client Reinstallation
# Adjust SMSSITECODE based on network zone (PS1 or DS1)

$managementPoint = 'YOUR_MP_FQDN'  # Get from team
$siteCode = 'DS1'  # or PS1 depending on zone

Write-Host "Uninstalling existing SCCM client..." -ForegroundColor Yellow
& "C:\Windows\ccmsetup\ccmsetup.exe" /uninstall
Start-Sleep -Seconds 120

Write-Host "Installing SCCM client..." -ForegroundColor Yellow
& ccmsetup.exe /mp:$managementPoint SMSSITECODE=$siteCode /forceinstall

Write-Host "Monitor installation: C:\Windows\ccmsetup\Logs\ccmsetup.log" -ForegroundColor Cyan
```

### 5.2 Verify Monitoring Agents

```powershell
# Check and restart monitoring agents

# Site24x7
$site24x7 = Get-Service 'Site24x7 Windows Agent' -EA SilentlyContinue
if ($site24x7) {
    Write-Host "Site24x7: $($site24x7.Status)"
    if ($site24x7.Status -ne 'Running') {
        Restart-Service $site24x7.Name
    }
}

# Qualys
$qualys = Get-Service 'QualysAgent' -EA SilentlyContinue
if ($qualys) {
    Write-Host "Qualys: $($qualys.Status)"
    if ($qualys.Status -ne 'Running') {
        Restart-Service $qualys.Name
    }
}
```

---

## Rollback Procedure

### When to Rollback
- Upgrade fails with unrecoverable error
- Critical application failure post-upgrade
- Domain authentication completely broken
- Stakeholder decision

### Rollback Steps

1. **Within 10 days (Windows rollback)**
   ```powershell
   # Windows built-in rollback (if available)
   # Check if rollback is possible
   Get-WindowsRollbackInfo
   
   # Initiate rollback
   Start-Process "systemreset.exe" -ArgumentList "-rollback"
   ```

2. **VM Restore from OpenStack Backup**
   - Contact #openstack_bots or use OpenStack portal
   - Reference: https://docs.openstack.int.gd3p.tools/features/dr_backups.html
   - Restore from pre-upgrade snapshot
   - Verify network configuration after restore

3. **Post-Rollback**
   - Verify domain connectivity
   - Check SCCM client
   - Notify stakeholders
   - Document failure reason for retry planning

---

## Known Issues and Lessons Learned

### DNS Settings Lost Post-Upgrade
**Symptom:** Domain login fails, `nslookup` fails, `Test-ComputerSecureChannel` returns False

**Cause:** DHCP may not repopulate DNS servers after upgrade, or static DNS settings get wiped

**Fix:**
```powershell
# Check DNS (will be empty if broken)
Get-DnsClientServerAddress -InterfaceAlias "Ethernet*" -AddressFamily IPv4

# Check pre-upgrade backup if you made one
Get-Content C:\UpgradeBackup*\Network\ipconfig.txt | Select-String "DNS Servers"

# Or check another working server on same network, then apply:
Set-DnsClientServerAddress -InterfaceAlias "Ethernet Instance 0" -ServerAddresses "10.255.250.5","10.255.251.5"
```

**Prevention:** Document DNS servers before upgrade and verify immediately after first reboot.

---

### Secure Channel Broken Post-Upgrade
**Symptom:** Domain logins fail, SIDs displayed instead of group names in local Administrators

**Cause:** Computer account password sync disrupted during upgrade

**Fix:**
```powershell
# Verify DNS works first (see above), then:
$cred = Get-Credential -UserName "DOMAIN\username" -Message "Enter domain credentials"
Test-ComputerSecureChannel -Repair -Credential $cred
```

**Note:** Requires domain account with rights to reset computer account passwords (typically Domain Admins or delegated OU admins).

---

### Site24x7 Agents Don't Auto-Start
**Symptom:** Site24x7 Windows Agent and APP Monitoring Agent are stopped post-upgrade

**Fix:**
```powershell
Get-Service 'Site24x7*' | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Start-Service -PassThru
```

**Prevention:** Add to post-upgrade validation checklist.

---

### IIS WebAdministration Module Broken
**Symptom:** `Get-Website` fails with COM class error (0x80040154 REGDB_E_CLASSNOTREG)

**Cause:** Legacy WebAdministration module COM registration doesn't survive upgrade cleanly

**Workaround:** Use the newer `IISAdministration` module instead:
```powershell
# Instead of:
Import-Module WebAdministration
Get-Website

# Use:
Import-Module IISAdministration
Get-IISSite
```

**Alternative:** Use `appcmd` directly:
```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" list site
```

---

### Component Store Corruption Cannot Be Repaired
**Symptom:** `DISM /RestoreHealth` fails with 0x800f081f even with ISO source

**Cause:** Corruption is in cumulative update packages (e.g., KB5041773) that don't exist in the RTM ISO

**Resolution:** Proceed with upgrade anyway. The in-place upgrade replaces the entire component store, so CU package corruption in the old OS doesn't block the upgrade.

```powershell
# To identify what's corrupted:
Select-String -Path C:\Windows\Logs\CBS\CBS.log -Pattern "corrupt|CBS_E_STORE_CORRUPTION" | Select-Object -Last 20
```

---

### Get-WindowsFeature Not Recognized
**Symptom:** `Get-WindowsFeature` command not found post-upgrade

**Cause:** ServerManager module not loaded or RSAT tools need reinstall

**Fix:**
```powershell
Import-Module ServerManager
# If still missing:
Install-WindowsFeature RSAT-Role-Tools -IncludeAllSubFeature
```

---

## Troubleshooting and Common Issues

### Issue: ISO Download Fails
```powershell
# Test repository connectivity
Test-NetConnection woerepo.mcs.int.gdcorp.tools -Port 443

# Alternative: Use browser to download, then copy to server
# https://woerepo.mcs.int.gdcorp.tools/installers/iso/
```

### Issue: "Edition cannot be upgraded"
- Verify ISO matches current edition (Standard/Datacenter)
- Check: `(Get-WindowsEdition -Online).Edition`

### Issue: Setup fails immediately
- Check C:\$WINDOWS.~BT\Sources\Panther\setupact.log
- Run setup without /quiet to see errors:
  ```powershell
  Start-Process "$driveLetter\setup.exe" -ArgumentList "/auto upgrade"
  ```

### Issue: Can't log in with domain account post-upgrade
1. Log in with local cactus account
2. Test secure channel: `Test-ComputerSecureChannel -Verbose`
3. Repair if needed: `Test-ComputerSecureChannel -Repair -Credential (Get-Credential)`

### Issue: SCCM client broken post-upgrade
- Full uninstall/reinstall required (see Phase 5.1)
- May need to delete: `C:\Windows\SMSCFG.INI`

### Issue: Services won't start
```powershell
# Check service dependencies
Get-Service <ServiceName> | Select-Object -ExpandProperty DependentServices
Get-Service <ServiceName> | Select-Object -ExpandProperty ServicesDependedOn

# Check event logs for specific errors
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7000,7001,7023} -MaxEvents 20
```

---

## Appendix - Quick Reference

### ISO URLs
| Version | URL |
|---------|-----|
| 2019 | `https://woerepo.mcs.int.gdcorp.tools/installers/iso/w2k19-s-64.iso` |
| 2022 | `https://woerepo.mcs.int.gdcorp.tools/installers/iso/w21h2-s-64.iso` |
| 2025 | `https://woerepo.mcs.int.gdcorp.tools/installers/iso/w24h2-s-64.iso` |

### Setup.exe Arguments
| Argument | Purpose |
|----------|---------|
| `/auto upgrade` | Perform upgrade (vs clean install) |
| `/quiet` | No UI (remove for troubleshooting) |
| `/noreboot` | Don't auto-reboot after upgrade |
| `/dynamicupdate disable` | Don't download updates during setup |
| `/compat IgnoreWarning` | Proceed despite compatibility warnings |
| `/showoobe none` | Skip OOBE screens |
| `/EULA accept` | Accept license agreement |
| `/copylogs <path>` | Copy setup logs to specified path |

### Key Log Locations
| Log | Path |
|-----|------|
| Setup progress | `C:\$WINDOWS.~BT\Sources\Panther\setupact.log` |
| Setup errors | `C:\$WINDOWS.~BT\Sources\Panther\setuperr.log` |
| Compatibility | `C:\$WINDOWS.~BT\Sources\Panther\CompatData*.xml` |
| Post-upgrade | `C:\Windows\Panther\setupact.log` |

### Contacts
- **Upgrade Issues:** #gpd-mscommon-services
- **OpenStack/Backups:** #openstack_bots
- **NCM/Load Balancer:** [appropriate channel]

---

*Document Version: 2.0 | Based on original guide by Andrew Griffiths*
