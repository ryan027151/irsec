# Reset All User Passwords
# Requires Administrator privileges

param(
    [Parameter(Mandatory=$false)]
    [int]$PasswordLength = 16
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

function New-SecurePassword {
    param([int]$Length = 16)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    $password = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $password
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "PasswordReset_$timestamp.txt"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  USER PASSWORD RESET UTILITY" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notmatch "^(DefaultAccount|Guest|WDAGUtilityAccount)$" }

$resetLog = @()

foreach ($user in $users) {
    $newPassword = New-SecurePassword -Length $PasswordLength
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
    
    try {
        Set-LocalUser -Name $user.Name -Password $securePassword -PasswordNeverExpires $false
        Write-Host "[SUCCESS] Reset password for user: $($user.Name)" -ForegroundColor Green
        
        $resetLog += [PSCustomObject]@{
            Username = $user.Name
            NewPassword = $newPassword
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Status = "Success"
        }
    }
    catch {
        Write-Host "[ERROR] Failed to reset password for user: $($user.Name)" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
        $resetLog += [PSCustomObject]@{
            Username = $user.Name
            NewPassword = "FAILED"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Status = "Failed: $($_.Exception.Message)"
        }
    }
}

$resetLog | Export-Csv -Path $logFile -NoTypeInformation
Write-Host "`n[INFO] Password reset log saved to: $logFile" -ForegroundColor Yellow
Write-Host "[CRITICAL] Store this file securely and delete after distributing passwords!" -ForegroundColor Red

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Users processed: $($users.Count)" -ForegroundColor White
Write-Host "  Successful resets: $(($resetLog | Where-Object {$_.Status -eq 'Success'}).Count)" -ForegroundColor Green
Write-Host "  Failed resets: $(($resetLog | Where-Object {$_.Status -ne 'Success'}).Count)" -ForegroundColor Red
Write-Host "======================================" -ForegroundColor Cyan
