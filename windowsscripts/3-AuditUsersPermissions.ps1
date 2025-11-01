# Audit All Users and Their Permissions
# Requires Administrator privileges

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = "UserAudit_$timestamp.html"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  USER & PERMISSIONS AUDIT" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] Collecting local user information..." -ForegroundColor Yellow
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description

Write-Host "[INFO] Analyzing group memberships..." -ForegroundColor Yellow
$userDetails = @()

foreach ($user in $users) {
    try {
        $groups = Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        } | Select-Object -ExpandProperty Name
        
        $isAdmin = $groups -contains "Administrators"
        $privilegeLevel = if ($isAdmin) { "ADMINISTRATOR" } else { "Standard User" }
        
        $userDetails += [PSCustomObject]@{
            Username = $user.Name
            Enabled = $user.Enabled
            PrivilegeLevel = $privilegeLevel
            Groups = ($groups -join ", ")
            LastLogon = $user.LastLogon
            PasswordLastSet = $user.PasswordLastSet
            PasswordExpires = $user.PasswordExpires
            Description = $user.Description
        }
        
        $color = if ($isAdmin) { "Red" } else { "White" }
        Write-Host "  $($user.Name): $privilegeLevel" -ForegroundColor $color
    }
    catch {
        Write-Host "[WARNING] Could not process user: $($user.Name)" -ForegroundColor Yellow
    }
}

Write-Host "`n[INFO] Checking for domain users with local access..." -ForegroundColor Yellow
try {
    $domainUsers = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.PrincipalSource -eq "ActiveDirectory" }
    if ($domainUsers) {
        Write-Host "[ALERT] Domain users with admin rights:" -ForegroundColor Red
        foreach ($du in $domainUsers) {
            Write-Host "  - $($du.Name)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "  Not domain-joined or no domain users found" -ForegroundColor Gray
}

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>User Audit Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #007ACC; padding-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #007ACC; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .admin { background-color: #ffebee; font-weight: bold; color: #c62828; }
        .enabled { color: green; font-weight: bold; }
        .disabled { color: red; font-weight: bold; }
        .summary { background-color: white; padding: 15px; margin-bottom: 20px; border-left: 4px solid #007ACC; }
    </style>
</head>
<body>
    <h1>User & Permissions Audit Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>Computer:</strong> $env:COMPUTERNAME<br>
        <strong>Total Users:</strong> $($userDetails.Count)<br>
        <strong>Administrators:</strong> $(($userDetails | Where-Object {$_.PrivilegeLevel -eq 'ADMINISTRATOR'}).Count)<br>
        <strong>Enabled Users:</strong> $(($userDetails | Where-Object {$_.Enabled -eq $true}).Count)
    </div>
    <table>
        <tr>
            <th>Username</th>
            <th>Status</th>
            <th>Privilege Level</th>
            <th>Groups</th>
            <th>Last Logon</th>
            <th>Password Last Set</th>
            <th>Description</th>
        </tr>
"@

foreach ($user in $userDetails) {
    $rowClass = if ($user.PrivilegeLevel -eq "ADMINISTRATOR") { " class='admin'" } else { "" }
    $statusClass = if ($user.Enabled) { "enabled" } else { "disabled" }
    $statusText = if ($user.Enabled) { "Enabled" } else { "Disabled" }
    
    $htmlReport += @"
        <tr$rowClass>
            <td>$($user.Username)</td>
            <td class='$statusClass'>$statusText</td>
            <td>$($user.PrivilegeLevel)</td>
            <td>$($user.Groups)</td>
            <td>$($user.LastLogon)</td>
            <td>$($user.PasswordLastSet)</td>
            <td>$($user.Description)</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
</body>
</html>
"@

$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n[SUCCESS] Audit report saved to: $reportFile" -ForegroundColor Green

$csvFile = "UserAudit_$timestamp.csv"
$userDetails | Export-Csv -Path $csvFile -NoTypeInformation
Write-Host "[SUCCESS] CSV export saved to: $csvFile" -ForegroundColor Green

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
