# Save as: 1B-DisablePINs.ps1
# Run AFTER password reset

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  DISABLE ALL USER PINs" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

foreach ($user in $users) {
    Write-Host "[INFO] Processing user: $($user.Name)" -ForegroundColor Yellow
    
    # Get user SID
    $sid = $user.SID.Value
    
    # PIN storage locations
    $pinPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}\$sid",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\HelloWorld\$sid"
    )
    
    foreach ($path in $pinPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "  [SUCCESS] Removed PIN data for $($user.Name)" -ForegroundColor Green
            }
            catch {
                Write-Host "  [WARNING] Could not remove PIN: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    
    # Remove NGC (Next Generation Credentials) folder - where PINs are stored
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC\$sid"
    if (Test-Path $ngcPath) {
        try {
            Remove-Item -Path $ngcPath -Recurse -Force -ErrorAction Stop
            Write-Host "  [SUCCESS] Removed NGC credentials for $($user.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARNING] Could not remove NGC folder: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[INFO] PIN removal complete!" -ForegroundColor Green
Write-Host "[INFO] Users will need to set up new PINs on next login" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan
```

---

## **Updated Master Script Order:**

Modify your security response to include PIN removal:
```
1. Enable Firewall ✅
2. Capture Network Connections ✅
3. Audit Users ✅
4. Reset Passwords ✅
5. Disable PINs ← ADD THIS!
6. Start Real-time Monitor ✅
