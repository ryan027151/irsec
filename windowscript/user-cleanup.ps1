# =========================================
# USER CLEANUP SCRIPT
# =========================================
# Removes unauthorized users and permissions

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "UserCleanup_$timestamp.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  USER CLEANUP" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-Transcript -Path $logFile

# Get all local users
$allUsers = Get-LocalUser

Write-Host "[INFO] Scanning for unauthorized users..." -ForegroundColor Yellow
Write-Host ""

# Find unauthorized users
$unauthorizedUsers = $allUsers | Where-Object { 
    $_.Name -notin $Global:TeamConfig.AuthorizedUsers -and
    $_.Name -notmatch "^(DefaultAccount|Guest|WDAGUtilityAccount)$"
}

if ($unauthorizedUsers.Count -eq 0) {
    Write-Host "[SUCCESS] No unauthorized users found!" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Found $($unauthorizedUsers.Count) unauthorized users:" -ForegroundColor Red
    Write-Host ""
    
    foreach ($user in $unauthorizedUsers) {
        Write-Host "  Username: $($user.Name)" -ForegroundColor Red
        Write-Host "  Enabled: $($user.Enabled)" -ForegroundColor Yellow
        Write-Host "  Last Logon: $($user.LastLogon)" -ForegroundColor Yellow
        Write-Host "  Description: $($user.Description)" -ForegroundColor Yellow
        
        # Check if user is admin
        $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        if ($isAdmin) {
            Write-Host "  PRIVILEGE: ADMINISTRATOR" -ForegroundColor Red
        }
        
        Write-Host ""
        $response = Read-Host "  Delete this user? (Y/N)"
        
        if ($response -eq "Y" -or $response -eq "y") {
            try {
                Remove-LocalUser -Name $user.Name -Confirm:$false
                Write-Host "  [DELETED] User $($user.Name) removed" -ForegroundColor Green
            }
            catch {
                Write-Host "  [ERROR] Failed to delete: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  [SKIPPED] User kept" -ForegroundColor Yellow
            
            # Disable instead?
            $disableResponse = Read-Host "  Disable this user instead? (Y/N)"
            if ($disableResponse -eq "Y" -or $disableResponse -eq "y") {
                try {
                    Disable-LocalUser -Name $user.Name
                    Write-Host "  [DISABLED] User $($user.Name) disabled" -ForegroundColor Yellow
                }
                catch {
                    Write-Host "  [ERROR] Failed to disable: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        Write-Host ""
    }
}

# Check Administrator group
Write-Host "[INFO] Checking Administrators group..." -ForegroundColor Yellow
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Current Administrators:" -ForegroundColor Cyan
foreach ($admin in $admins) {
    $username = $admin.Name.Split('\')[-1]
    $isAuthorized = $username -in $Global:TeamConfig.AuthorizedAdmins
    
    if ($isAuthorized) {
        Write-Host "  [OK] $($admin.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [UNAUTHORIZED] $($admin.Name)" -ForegroundColor Red
        
        $response = Read-Host "  Remove from Administrators group? (Y/N)"
        if ($response -eq "Y" -or $response -eq "y") {
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name -Confirm:$false
                Write-Host "  [REMOVED] $($admin.Name) removed from Administrators" -ForegroundColor Green
            }
            catch {
                Write-Host "  [ERROR] Failed to remove: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# Check Remote Desktop Users group
Write-Host ""
Write-Host "[INFO] Checking Remote Desktop Users group..." -ForegroundColor Yellow
$rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue

if ($rdpUsers) {
    Write-Host ""
    Write-Host "Current RDP Users:" -ForegroundColor Cyan
    foreach ($rdpUser in $rdpUsers) {
        $username = $rdpUser.Name.Split('\')[-1]
        Write-Host "  $($rdpUser.Name)" -ForegroundColor Yellow
        
        $response = Read-Host "  Keep this user in RDP group? (Y/N)"
        if ($response -eq "N" -or $response -eq "n") {
            try {
                Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $rdpUser.Name -Confirm:$false
                Write-Host "  [REMOVED] $($rdpUser.Name) removed from RDP Users" -ForegroundColor Green
            }
            catch {
                Write-Host "  [ERROR] Failed to remove: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  USER CLEANUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Stop-Transcript
Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
Write-Host ""
