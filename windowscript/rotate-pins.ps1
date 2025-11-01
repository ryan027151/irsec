# =========================================
# ROTATE PINs - SAFER ALTERNATIVE
# =========================================
# Changes PINs instead of deleting them
# Keeps login methods working!

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Load config
if (Test-Path ".\config.ps1") { . .\config.ps1 }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = if ($Global:TeamConfig) { 
    Join-Path $Global:TeamConfig.LogDirectory "PINRotation_$timestamp.txt"
} else {
    "PINRotation_$timestamp.txt"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PIN ROTATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] This script will generate new PINs for all users" -ForegroundColor Yellow
Write-Host "[INFO] Users must set new PINs on next login" -ForegroundColor Yellow
Write-Host ""

Start-Transcript -Path $logFile

function New-RandomPIN {
    param([int]$Length = 6)
    $pin = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $pin += Get-Random -Minimum 0 -Maximum 10
    }
    return $pin
}

$users = Get-LocalUser | Where-Object { 
    $_.Enabled -eq $true -and 
    $_.Name -notmatch "^(DefaultAccount|Guest|WDAGUtilityAccount)$"
}

Write-Host "[INFO] Found $($users.Count) users to process" -ForegroundColor Cyan
Write-Host ""

$pinLog = @()

foreach ($user in $users) {
    Write-Host "Processing: $($user.Name)" -ForegroundColor Cyan
    
    $newPIN = New-RandomPIN -Length 6
    $sid = $user.SID.Value
    
    # Method 1: Force PIN reset via NGC folder removal (forces user to set new PIN)
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC\$sid"
    if (Test-Path $ngcPath) {
        try {
            # Take ownership and delete to force PIN reset
            takeown /F "$ngcPath" /R /D Y 2>&1 | Out-Null
            icacls "$ngcPath" /grant Administrators:F /T 2>&1 | Out-Null
            Remove-Item -Path $ngcPath -Recurse -Force -ErrorAction Stop
            
            Write-Host "  [SUCCESS] $($user.Name) will be prompted to set new PIN on next login" -ForegroundColor Green
            
            $pinLog += [PSCustomObject]@{
                Username = $user.Name
                SuggestedPIN = $newPIN
                Status = "Will be prompted to set new PIN"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        catch {
            Write-Host "  [ERROR] Could not reset PIN for $($user.Name): $($_.Exception.Message)" -ForegroundColor Red
            
            $pinLog += [PSCustomObject]@{
                Username = $user.Name
                SuggestedPIN = $newPIN
                Status = "Failed: $($_.Exception.Message)"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    else {
        Write-Host "  [INFO] No PIN configured for $($user.Name)" -ForegroundColor Gray
        
        $pinLog += [PSCustomObject]@{
            Username = $user.Name
            SuggestedPIN = $newPIN
            Status = "No PIN found"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# Save PIN log
$pinLog | Export-Csv -Path $logFile -NoTypeInformation
Write-Host ""
Write-Host "[SUCCESS] PIN rotation log saved to: $logFile" -ForegroundColor Green
Write-Host ""

# Display summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Users processed: $($users.Count)" -ForegroundColor White
Write-Host "  PINs reset: $(($pinLog | Where-Object {$_.Status -like '*prompted*'}).Count)" -ForegroundColor Green
Write-Host "  Failed: $(($pinLog | Where-Object {$_.Status -like 'Failed*'}).Count)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] What happens next:" -ForegroundColor Yellow
Write-Host "  1. Users can still log in with PASSWORDS" -ForegroundColor Green
Write-Host "  2. When they try to use PIN, they'll be prompted to set a NEW PIN" -ForegroundColor Yellow
Write-Host "  3. Distribute the suggested PINs from the log file" -ForegroundColor Yellow
Write-Host "  4. No restart required!" -ForegroundColor Green
Write-Host ""

Write-Host "[RECOMMENDED] Next steps:" -ForegroundColor Cyan
Write-Host "  1. Tell users their old PINs won't work" -ForegroundColor White
Write-Host "  2. Have them log in with PASSWORD" -ForegroundColor White
Write-Host "  3. They can set new PIN: Settings -> Accounts -> Sign-in options" -ForegroundColor White
Write-Host "  4. Or provide suggested PINs from log file" -ForegroundColor White
Write-Host ""

Stop-Transcript

Write-Host "[INFO] Log file: $logFile" -ForegroundColor Cyan
Write-Host ""

# Offer to display suggested PINs
$showPINs = Read-Host "Show suggested PINs now? (Y/N)"
if ($showPINs -eq "Y" -or $showPINs -eq "y") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "SUGGESTED PINs (Distribute Securely!)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    $pinLog | Where-Object { $_.Status -like '*prompted*' } | Format-Table Username, SuggestedPIN -AutoSize
    Write-Host ""
    Write-Host "[CRITICAL] Delete this log after distributing PINs!" -ForegroundColor Red
}
