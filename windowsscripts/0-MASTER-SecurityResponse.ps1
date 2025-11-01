# MASTER Security Incident Response Script
# Executes all security measures in proper sequence
# Requires Administrator privileges

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordReset,
    [Parameter(Mandatory=$false)]
    [switch]$SkipFirewall,
    [Parameter(Mandatory=$false)]
    [switch]$SkipAudit,
    [Parameter(Mandatory=$false)]
    [switch]$SkipNetworkCapture,
    [Parameter(Mandatory=$false)]
    [switch]$StartMonitor
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ErrorActionPreference = "Continue"

Write-Host "======================================" -ForegroundColor Red
Write-Host "  SECURITY INCIDENT RESPONSE" -ForegroundColor Red
Write-Host "  MASTER EXECUTION SCRIPT" -ForegroundColor Red
Write-Host "======================================" -ForegroundColor Red
Write-Host ""
Write-Host "[WARNING] This script will perform the following actions:" -ForegroundColor Yellow
Write-Host "  1. Reset all user passwords (if not skipped)" -ForegroundColor White
Write-Host "  2. Enable Windows Firewall for all profiles (if not skipped)" -ForegroundColor White
Write-Host "  3. Audit all users and permissions (if not skipped)" -ForegroundColor White
Write-Host "  4. Capture network connection snapshots (if not skipped)" -ForegroundColor White
Write-Host "  5. Optionally start real-time monitoring" -ForegroundColor White
Write-Host ""

$response = Read-Host "Do you want to continue? (YES/NO)"
if ($response -ne "YES") {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit 0
}

Write-Host "`n[INFO] Starting security response at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipFirewall) {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "STEP 1: Enabling Firewall" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    if (Test-Path ".\2-EnableFirewall.ps1") {
        & ".\2-EnableFirewall.ps1"
    } else {
        Write-Host "[ERROR] 2-EnableFirewall.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

if (-not $SkipNetworkCapture) {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "STEP 2: Capturing Network Connections" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    if (Test-Path ".\4-CaptureNetworkConnections.ps1") {
        & ".\4-CaptureNetworkConnections.ps1" -SnapshotCount 5 -SnapshotInterval 3
    } else {
        Write-Host "[ERROR] 4-CaptureNetworkConnections.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

if (-not $SkipAudit) {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "STEP 3: Auditing Users and Permissions" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    if (Test-Path ".\3-AuditUsersPermissions.ps1") {
        & ".\3-AuditUsersPermissions.ps1"
    } else {
        Write-Host "[ERROR] 3-AuditUsersPermissions.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

if (-not $SkipPasswordReset) {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "STEP 4: Resetting User Passwords" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "[WARNING] This will log out all users!" -ForegroundColor Red
    
    $confirm = Read-Host "Proceed with password reset? (YES/NO)"
    if ($confirm -eq "YES") {
        if (Test-Path ".\1-ResetPasswords.ps1") {
            & ".\1-ResetPasswords.ps1"
        } else {
            Write-Host "[ERROR] 1-ResetPasswords.ps1 not found!" -ForegroundColor Red
        }
    } else {
        Write-Host "[SKIPPED] Password reset cancelled by user" -ForegroundColor Yellow
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

if ($StartMonitor) {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "STEP 5: Starting Real-time Monitor" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    if (Test-Path ".\5-RealtimeSecurityMonitor.ps1") {
        Write-Host "[INFO] Launching monitor in new window..." -ForegroundColor Yellow
        Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `".\5-RealtimeSecurityMonitor.ps1`" -EnableSound" -Verb RunAs
        Write-Host "[INFO] Monitor started in separate window" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] 5-RealtimeSecurityMonitor.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "======================================" -ForegroundColor Green
Write-Host "  SECURITY RESPONSE COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review all generated reports and logs" -ForegroundColor White
Write-Host "  2. Distribute new passwords securely" -ForegroundColor White
Write-Host "  3. Investigate suspicious connections/processes" -ForegroundColor White
Write-Host "  4. Consider running antivirus/antimalware scans" -ForegroundColor White
Write-Host "  5. Review firewall logs for blocked connections" -ForegroundColor White
Write-Host "  6. Check Windows Event Logs for security events" -ForegroundColor White
Write-Host ""
Write-Host "[INFO] Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
