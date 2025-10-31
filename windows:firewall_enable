# Enable Windows Firewall for All Profiles
# Requires Administrator privileges

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  WINDOWS FIREWALL ACTIVATION" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] Current Firewall Status:" -ForegroundColor Yellow
$currentStatus = Get-NetFirewallProfile -All | Select-Object Name, Enabled

foreach ($profile in $currentStatus) {
    $status = if ($profile.Enabled) { "ENABLED" } else { "DISABLED" }
    $color = if ($profile.Enabled) { "Green" } else { "Red" }
    Write-Host "  $($profile.Name): $status" -ForegroundColor $color
}

Write-Host "`n[ACTION] Enabling firewall for all profiles..." -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "[SUCCESS] Firewall enabled for all profiles" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to enable firewall" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[ACTION] Configuring firewall rules..." -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Host "[SUCCESS] Default actions configured (Block Inbound, Allow Outbound)" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Could not set default actions" -ForegroundColor Yellow
}

Write-Host "`n[INFO] Updated Firewall Status:" -ForegroundColor Yellow
$newStatus = Get-NetFirewallProfile -All | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

foreach ($profile in $newStatus) {
    Write-Host "`n  Profile: $($profile.Name)" -ForegroundColor Cyan
    Write-Host "    Enabled: $($profile.Enabled)" -ForegroundColor Green
    Write-Host "    Default Inbound: $($profile.DefaultInboundAction)" -ForegroundColor White
    Write-Host "    Default Outbound: $($profile.DefaultOutboundAction)" -ForegroundColor White
}

Write-Host "`n[ACTION] Enabling firewall logging..." -ForegroundColor Yellow
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked True -LogMaxSizeKilobytes 4096
    $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    Write-Host "[SUCCESS] Firewall logging enabled" -ForegroundColor Green
    Write-Host "[INFO] Log location: $logPath" -ForegroundColor Yellow
}
catch {
    Write-Host "[WARNING] Could not enable logging: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "  FIREWALL CONFIGURATION COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
