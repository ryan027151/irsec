# =========================================
# CHECK USERS SCRIPT
# =========================================
# Audits users and flags non-standard accounts

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Load config
if (Test-Path ".\config.ps1") { . .\config.ps1 } else {
    Write-Error "config.ps1 not found!"
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $Global:TeamConfig.LogDirectory "UserAudit_$timestamp.html"
$csvFile = Join-Path $Global:TeamConfig.LogDirectory "UserAudit_$timestamp.csv"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  USER AUDIT" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Collect user information
Write-Host "[INFO] Collecting user information..." -ForegroundColor Yellow
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description

# Analyze each user
Write-Host "[INFO] Analyzing user permissions..." -ForegroundColor Yellow
$userDetails = @()

foreach ($user in $users) {
    try {
        $groups = Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        } | Select-Object -ExpandProperty Name
        
        $isAdmin = $groups -contains "Administrators"
        $isRDP = $groups -contains "Remote Desktop Users"
        $isAuthorized = $user.Name -in $Global:TeamConfig.AuthorizedUsers
        $isAuthorizedAdmin = $user.Name -in $Global:TeamConfig.AuthorizedAdmins
        
        # Determine status
        $status = "OK"
        $warnings = @()
        
        if (-not $isAuthorized) {
            $status = "UNAUTHORIZED"
            $warnings += "User not in authorized list"
        }
        
        if ($isAdmin -and -not $isAuthorizedAdmin) {
            $status = "CRITICAL"
            $warnings += "Unauthorized administrator"
        }
        
        $privilegeLevel = if ($isAdmin) { "Administrator" } else { "Standard User" }
        
        $userDetails += [PSCustomObject]@{
            Username = $user.Name
            Status = $status
            Enabled = $user.Enabled
            PrivilegeLevel = $privilegeLevel
            IsRDP = $isRDP
            Groups = ($groups -join ", ")
            LastLogon = $user.LastLogon
            PasswordLastSet = $user.PasswordLastSet
            PasswordExpires = $user.PasswordExpires
            Description = $user.Description
            Warnings = ($warnings -join "; ")
        }
        
        # Display on console
        $color = switch ($status) {
            "CRITICAL" { "Red" }
            "UNAUTHORIZED" { "Yellow" }
            default { "Green" }
        }
        Write-Host "  $($user.Name): $status - $privilegeLevel" -ForegroundColor $color
    }
    catch {
        Write-Host "[WARNING] Could not process user: $($user.Name)" -ForegroundColor Yellow
    }
}

# Check for domain users with local admin
Write-Host ""
Write-Host "[INFO] Checking for domain users with local admin..." -ForegroundColor Yellow
try {
    $domainAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
        Where-Object { $_.PrincipalSource -eq "ActiveDirectory" }
    
    if ($domainAdmins) {
        Write-Host "[ALERT] Domain users with admin rights:" -ForegroundColor Red
        foreach ($da in $domainAdmins) {
            Write-Host "  - $($da.Name)" -ForegroundColor Red
        }
    } else {
        Write-Host "  No domain admin accounts found" -ForegroundColor Green
    }
}
catch {
    Write-Host "  Not domain-joined" -ForegroundColor Gray
}

# Generate HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>User Audit Report - $($Global:TeamConfig.TeamName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #007ACC; padding-bottom: 10px; }
        .summary { background-color: white; padding: 15px; margin-bottom: 20px; border-left: 4px solid #007ACC; }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #007ACC; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .critical { background-color: #ffebee; color: #c62828; font-weight: bold; }
        .unauthorized { background-color: #fff3e0; color: #e65100; }
        .ok { color: #2e7d32; }
        .admin { font-weight: bold; }
    </style>
</head>
<body>
    <h1>User Audit Report</h1>
    <div class="summary">
        <strong>Team:</strong> $($Global:TeamConfig.TeamName)<br>
        <strong>Team Number:</strong> $($Global:TeamConfig.TeamNumber)<br>
        <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>Computer:</strong> $env:COMPUTERNAME<br>
        <strong>Total Users:</strong> $($userDetails.Count)<br>
        <strong>Administrators:</strong> $(($userDetails | Where-Object {$_.PrivilegeLevel -eq 'Administrator'}).Count)<br>
        <strong>Unauthorized Users:</strong> $(($userDetails | Where-Object {$_.Status -ne 'OK'}).Count)
    </div>
    <table>
        <tr>
            <th>Username</th>
            <th>Status</th>
            <th>Enabled</th>
            <th>Privilege</th>
            <th>RDP Access</th>
            <th>Groups</th>
            <th>Last Logon</th>
            <th>Password Set</th>
            <th>Warnings</th>
        </tr>
"@

foreach ($user in $userDetails) {
    $statusClass = $user.Status.ToLower()
    $adminClass = if ($user.PrivilegeLevel -eq "Administrator") { " admin" } else { "" }
    
    $htmlReport += @"
        <tr class="$statusClass$adminClass">
            <td>$($user.Username)</td>
            <td>$($user.Status)</td>
            <td>$($user.Enabled)</td>
            <td>$($user.PrivilegeLevel)</td>
            <td>$($user.IsRDP)</td>
            <td>$($user.Groups)</td>
            <td>$($user.LastLogon)</td>
            <td>$($user.PasswordLastSet)</td>
            <td>$($user.Warnings)</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
</body>
</html>
"@

# Save reports
$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
$userDetails | Export-Csv -Path $csvFile -NoTypeInformation

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  USER AUDIT COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[SUCCESS] HTML report: $reportFile" -ForegroundColor Green
Write-Host "[SUCCESS] CSV export: $csvFile" -ForegroundColor Green
Write-Host ""
