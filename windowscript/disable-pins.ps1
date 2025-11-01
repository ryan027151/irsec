# =========================================
# DISABLE PINs AND BIOMETRICS
# =========================================
# Removes PINs and disables Windows Hello

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Load config
if (Test-Path ".\config.ps1") { . .\config.ps1 }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = if ($Global:TeamConfig) { 
    Join-Path $Global:TeamConfig.LogDirectory "PINDisable_$timestamp.txt"
} else {
    "PINDisable_$timestamp.txt"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DISABLE PINs AND BIOMETRICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-Transcript -Path $logFile

# Disable Windows Hello completely
Write-Host "[ACTION] Disabling Windows Hello..." -ForegroundColor Yellow
try {
    $passportPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    if (-not (Test-Path $passportPath)) {
        New-Item -Path $passportPath -Force | Out-Null
    }
    Set-ItemProperty -Path $passportPath -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Host "[SUCCESS] Windows Hello disabled" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Could not disable Windows Hello: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Get all users
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

Write-Host ""
Write-Host "[ACTION] Removing PINs for all users..." -ForegroundColor Yellow

foreach ($user in $users) {
    Write-Host "  Processing: $($user.Name)" -ForegroundColor Cyan
    
    $sid = $user.SID.Value
    $removed = $false
    
    # Remove PIN credential provider data
    $pinPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}\$sid"
    )
    
    foreach ($path in $pinPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "    [SUCCESS] Removed PIN registry data" -ForegroundColor Green
                $removed = $true
            }
            catch {
                Write-Host "    [WARNING] Could not remove PIN registry: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    
    # Remove NGC (Next Generation Credentials) folder
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC\$sid"
    if (Test-Path $ngcPath) {
        try {
            # Take ownership and grant permissions
            takeown /F $ngcPath /R /D Y | Out-Null
            icacls $ngcPath /grant Administrators:F /T | Out-Null
            Remove-Item -Path $ngcPath -Recurse -Force -ErrorAction Stop
            Write-Host "    [SUCCESS] Removed NGC credentials" -ForegroundColor Green
            $removed = $true
        }
        catch {
            Write-Host "    [WARNING] Could not remove NGC folder: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    if (-not $removed) {
        Write-Host "    [INFO] No PIN data found for this user" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  PIN REMOVAL COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Users must now log in with passwords" -ForegroundColor Yellow
Write-Host "[INFO] They can set new PINs after logging in with new passwords" -ForegroundColor Yellow
Write-Host "[INFO] A system restart is recommended for full effect" -ForegroundColor Yellow
Write-Host ""

Stop-Transcript
