# =========================================
# PASSWORD RESET SCRIPT - INTERACTIVE
# =========================================
# Resets passwords with user selection

param(
    [Parameter(Mandatory=$false)]
    [int]$PasswordLength = 16,
    [Parameter(Mandatory=$false)]
    [switch]$ResetAll
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Load config
if (Test-Path ".\config.ps1") { . .\config.ps1 } else {
    Write-Error "config.ps1 not found!"
    exit 1
}

function New-SecurePassword {
    param([int]$Length = 16)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    $password = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $password
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $Global:TeamConfig.LogDirectory "PasswordReset_$timestamp.txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PASSWORD RESET UTILITY - INTERACTIVE" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get all local users
$allUsers = Get-LocalUser | Where-Object { 
    $_.Enabled -eq $true -and 
    $_.Name -notmatch "^(DefaultAccount|Guest|WDAGUtilityAccount)$"
}

Write-Host "[INFO] Found $($allUsers.Count) enabled users" -ForegroundColor Cyan
Write-Host ""

# Display users and let user select
if (-not $ResetAll) {
    Write-Host "Select users to reset passwords:" -ForegroundColor Yellow
    Write-Host "(You can select multiple users)" -ForegroundColor Gray
    Write-Host ""
    
    $selectedUsers = @()
    $userIndex = 1
    
    foreach ($user in $allUsers) {
        $isAuthorized = $user.Name -in $Global:TeamConfig.AuthorizedUsers
        $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        
        $statusColor = if ($isAuthorized) { "Green" } else { "Yellow" }
        $adminTag = if ($isAdmin) { " [ADMIN]" } else { "" }
        $authTag = if ($isAuthorized) { " [Authorized]" } else { " [NOT in authorized list]" }
        
        Write-Host "[$userIndex] " -NoNewline -ForegroundColor Cyan
        Write-Host "$($user.Name)$adminTag$authTag" -ForegroundColor $statusColor
        Write-Host "    Last Password Set: $($user.PasswordLastSet)" -ForegroundColor Gray
        Write-Host "    Last Logon: $($user.LastLogon)" -ForegroundColor Gray
        
        $userIndex++
    }
    
    Write-Host ""
    Write-Host "[A] Reset ALL users" -ForegroundColor Yellow
    Write-Host "[O] Reset only AUTHORIZED users" -ForegroundColor Green
    Write-Host "[Q] Quit without resetting" -ForegroundColor Red
    Write-Host ""
    
    $selection = Read-Host "Enter your choice (1-$($allUsers.Count), A, O, or Q)"
    
    if ($selection -eq "Q" -or $selection -eq "q") {
        Write-Host "[INFO] Operation cancelled by user" -ForegroundColor Yellow
        exit 0
    }
    elseif ($selection -eq "A" -or $selection -eq "a") {
        $selectedUsers = $allUsers
        Write-Host "[INFO] Resetting ALL $($selectedUsers.Count) users" -ForegroundColor Yellow
    }
    elseif ($selection -eq "O" -or $selection -eq "o") {
        $selectedUsers = $allUsers | Where-Object { $_.Name -in $Global:TeamConfig.AuthorizedUsers }
        Write-Host "[INFO] Resetting $($selectedUsers.Count) authorized users" -ForegroundColor Green
    }
    else {
        # Parse individual selections (supports comma-separated like "1,3,5")
        $selections = $selection -split "," | ForEach-Object { $_.Trim() }
        
        foreach ($sel in $selections) {
            if ($sel -match '^\d+$') {
                $index = [int]$sel - 1
                if ($index -ge 0 -and $index -lt $allUsers.Count) {
                    $selectedUsers += $allUsers[$index]
                }
                else {
                    Write-Host "[WARNING] Invalid selection: $sel" -ForegroundColor Yellow
                }
            }
        }
        
        if ($selectedUsers.Count -eq 0) {
            Write-Host "[ERROR] No valid users selected!" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "[INFO] Selected $($selectedUsers.Count) user(s):" -ForegroundColor Cyan
        foreach ($u in $selectedUsers) {
            Write-Host "  - $($u.Name)" -ForegroundColor White
        }
    }
    
    Write-Host ""
    $confirm = Read-Host "Proceed with password reset for these users? (YES/NO)"
    if ($confirm -ne "YES") {
        Write-Host "[INFO] Operation cancelled" -ForegroundColor Yellow
        exit 0
    }
}
else {
    # Reset all mode (from parameter)
    $selectedUsers = $allUsers
    Write-Host "[INFO] Resetting ALL $($selectedUsers.Count) users (ResetAll parameter)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Resetting Passwords..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$resetLog = @()

foreach ($user in $selectedUsers) {
    $newPassword = New-SecurePassword -Length $PasswordLength
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
    
    Write-Host "Processing: $($user.Name)..." -NoNewline
    
    try {
        Set-LocalUser -Name $user.Name -Password $securePassword -PasswordNeverExpires $false
        Write-Host " [SUCCESS]" -ForegroundColor Green
        
        $resetLog += [PSCustomObject]@{
            Username = $user.Name
            NewPassword = $newPassword
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Status = "Success"
        }
    }
    catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        
        $resetLog += [PSCustomObject]@{
            Username = $user.Name
            NewPassword = "FAILED"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Status = "Failed: $($_.Exception.Message)"
        }
    }
}

# Save log
$resetLog | Export-Csv -Path $logFile -NoTypeInformation
Write-Host ""
Write-Host "[SUCCESS] Password reset log saved to: $logFile" -ForegroundColor Green
Write-Host "[CRITICAL] Store this file securely!" -ForegroundColor Red
Write-Host ""

# Display passwords
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NEW PASSWORDS (Secure This Info!)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$successfulResets = $resetLog | Where-Object {$_.Status -eq 'Success'}
$successfulResets | Format-Table Username, NewPassword -AutoSize

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Users processed: $($selectedUsers.Count)" -ForegroundColor White
Write-Host "  Successful: $(($resetLog | Where-Object {$_.Status -eq 'Success'}).Count)" -ForegroundColor Green
Write-Host "  Failed: $(($resetLog | Where-Object {$_.Status -ne 'Success'}).Count)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Users can still log in with PINs/biometrics!" -ForegroundColor Yellow
Write-Host "[INFO] Run rotate-pins.ps1 to invalidate old PINs" -ForegroundColor Yellow
Write-Host ""
Write-Host "[CRITICAL] Delete $logFile after distributing passwords!" -ForegroundColor Red
Write-Host ""
