# =========================================
# MASTER CCDC SECURITY RESPONSE SCRIPT
# =========================================
# This script coordinates all security responses
# and launches continuous monitoring

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordReset,
    [Parameter(Mandatory=$false)]
    [switch]$SkipPINDisable,
    [Parameter(Mandatory=$false)]
    [switch]$SkipFirewall,
    [Parameter(Mandatory=$false)]
    [switch]$SkipIncidentResponse,
    [Parameter(Mandatory=$false)]
    [switch]$ContinuousMode
)

# Check Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

$ErrorActionPreference = "Continue"

# Load team configuration
if (-not (Test-Path ".\config.ps1")) {
    Write-Error "config.ps1 not found! Please create it first."
    exit 1
}
. .\config.ps1

Write-Host "========================================" -ForegroundColor Red
Write-Host "  CCDC SECURITY INCIDENT RESPONSE" -ForegroundColor Red
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "[INFO] This script will execute security response procedures" -ForegroundColor Yellow
Write-Host ""

# Create session log
$sessionLog = Join-Path $Global:TeamConfig.LogDirectory "MasterScript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $sessionLog

Write-Host "[INFO] Session log: $sessionLog" -ForegroundColor Cyan
Write-Host ""

$response = Read-Host "Do you want to continue? (YES/NO)"
if ($response -ne "YES") {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    Stop-Transcript
    exit 0
}

Write-Host ""

# ==========================================
# STEP 1: INCIDENT RESPONSE DATA COLLECTION
# ==========================================
if (-not $SkipIncidentResponse) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "STEP 1: Incident Response Data Collection" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (Test-Path ".\incident-response.ps1") {
        & ".\incident-response.ps1"
    } else {
        Write-Host "[ERROR] incident-response.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ==========================================
# STEP 2: FIREWALL LOCKDOWN
# ==========================================
if (-not $SkipFirewall) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "STEP 2: Firewall Lockdown" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (Test-Path ".\firewall-lockdown.ps1") {
        & ".\firewall-lockdown.ps1"
    } else {
        Write-Host "[ERROR] firewall-lockdown.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ==========================================
# STEP 3: USER CLEANUP & AUDIT
# ==========================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STEP 3: User Cleanup & Audit" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path ".\user-cleanup.ps1") {
    & ".\user-cleanup.ps1"
} else {
    Write-Host "[ERROR] user-cleanup.ps1 not found!" -ForegroundColor Red
}

if (Test-Path ".\check-users.ps1") {
    & ".\check-users.ps1"
} else {
    Write-Host "[ERROR] check-users.ps1 not found!" -ForegroundColor Red
}
Write-Host ""
Start-Sleep -Seconds 2

# ==========================================
# STEP 4: PASSWORD RESET
# ==========================================
if (-not $SkipPasswordReset) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "STEP 4: Password Reset" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[WARNING] This will reset passwords for all users!" -ForegroundColor Red
    
    $confirm = Read-Host "Proceed with password reset? (YES/NO)"
    if ($confirm -eq "YES") {
        if (Test-Path ".\reset-passwords.ps1") {
            & ".\reset-passwords.ps1"
        } else {
            Write-Host "[ERROR] reset-passwords.ps1 not found!" -ForegroundColor Red
        }
    } else {
        Write-Host "[SKIPPED] Password reset cancelled" -ForegroundColor Yellow
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ==========================================
# STEP 5: DISABLE PINs AND BIOMETRICS
# ==========================================
if (-not $SkipPINDisable) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "STEP 5: Disable PINs and Biometrics" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (Test-Path ".\disable-pins.ps1") {
        & ".\disable-pins.ps1"
    } else {
        Write-Host "[ERROR] disable-pins.ps1 not found!" -ForegroundColor Red
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ==========================================
# STEP 6: SERVICE REPAIR
# ==========================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STEP 6: Critical Service Repair" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path ".\service-repair.ps1") {
    & ".\service-repair.ps1"
} else {
    Write-Host "[ERROR] service-repair.ps1 not found!" -ForegroundColor Red
}
Write-Host ""
Start-Sleep -Seconds 2

# ==========================================
# STEP 7: STARTUP INTEGRITY CHECK
# ==========================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STEP 7: Startup Integrity Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path ".\startup-integrity.ps1") {
    & ".\startup-integrity.ps1"
} else {
    Write-Host "[ERROR] startup-integrity.ps1 not found!" -ForegroundColor Red
}
Write-Host ""
Start-Sleep -Seconds 2

# ==========================================
# STEP 8: LAUNCH CONTINUOUS MONITORING
# ==========================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STEP 8: Launch Continuous Monitoring" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[INFO] Starting continuous monitoring services..." -ForegroundColor Yellow

# Launch Network Monitor
if (Test-Path ".\continuous-network-monitor.ps1") {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `".\continuous-network-monitor.ps1`"" -Verb RunAs
    Write-Host "[SUCCESS] Network monitor started in new window" -ForegroundColor Green
}

# Launch Process Monitor
if (Test-Path ".\continuous-process-monitor.ps1") {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `".\continuous-process-monitor.ps1`"" -Verb RunAs
    Write-Host "[SUCCESS] Process monitor started in new window" -ForegroundColor Green
}

# Launch Service Watchdog
if (Test-Path ".\service-watchdog.ps1") {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `".\service-watchdog.ps1`"" -Verb RunAs
    Write-Host "[SUCCESS] Service watchdog started in new window" -ForegroundColor Green
}

Write-Host ""

# ==========================================
# COMPLETION
# ==========================================
Write-Host "========================================" -ForegroundColor Green
Write-Host "  SECURITY RESPONSE COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Review incident response data in: $($Global:TeamConfig.LogDirectory)" -ForegroundColor White
Write-Host "  2. Distribute new passwords securely to team members" -ForegroundColor White
Write-Host "  3. Monitor the continuous monitoring windows" -ForegroundColor White
Write-Host "  4. Check firewall rules and allowed IPs" -ForegroundColor White
Write-Host "  5. Verify all critical services are running" -ForegroundColor White
Write-Host ""
Write-Host "[INFO] Monitoring windows are running in background" -ForegroundColor Cyan
Write-Host "[INFO] Press Ctrl+C in those windows to stop monitoring" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Session log saved to: $sessionLog" -ForegroundColor Cyan

Stop-Transcript
