# =========================================
# SERVICE REPAIR SCRIPT
# =========================================
# Ensures critical services are running

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "ServiceRepair_$timestamp.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CRITICAL SERVICE REPAIR" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-Transcript -Path $logFile

Write-Host "[INFO] Checking $($Global:TeamConfig.CriticalServices.Count) critical services..." -ForegroundColor Yellow
Write-Host ""

$results = @()

foreach ($serviceName in $Global:TeamConfig.CriticalServices) {
    Write-Host "Checking: $serviceName" -ForegroundColor Cyan
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Host "  [NOT FOUND] Service does not exist on this system" -ForegroundColor Gray
            $results += [PSCustomObject]@{
                Service = $serviceName
                InitialStatus = "Not Found"
                FinalStatus = "Not Found"
                Action = "None"
                Result = "N/A"
            }
            continue
        }
        
        $initialStatus = $service.Status
        $initialStartType = $service.StartType
        $actionsTaken = @()
        
        Write-Host "  Initial Status: $initialStatus" -ForegroundColor $(if ($initialStatus -eq "Running") { "Green" } else { "Red" })
        Write-Host "  Startup Type: $initialStartType" -ForegroundColor $(if ($initialStartType -eq "Automatic") { "Green" } else { "Yellow" })
        
        # Fix startup type if disabled or manual
        if ($initialStartType -eq "Disabled") {
            Write-Host "  [ACTION] Service is DISABLED - Setting to Automatic..." -ForegroundColor Yellow
            try {
                Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                Write-Host "  [SUCCESS] Startup type set to Automatic" -ForegroundColor Green
                $actionsTaken += "Set startup to Automatic"
            }
            catch {
                Write-Host "  [ERROR] Failed to change startup type: $($_.Exception.Message)" -ForegroundColor Red
                $actionsTaken += "FAILED to set startup type"
            }
        } elseif ($initialStartType -eq "Manual") {
            Write-Host "  [ACTION] Service is Manual - Setting to Automatic..." -ForegroundColor Yellow
            try {
                Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                Write-Host "  [SUCCESS] Startup type set to Automatic" -ForegroundColor Green
                $actionsTaken += "Set startup to Automatic"
            }
            catch {
                Write-Host "  [ERROR] Failed to change startup type: $($_.Exception.Message)" -ForegroundColor Red
                $actionsTaken += "FAILED to set startup type"
            }
        }
        
        # Start service if stopped
        if ($initialStatus -ne "Running") {
            Write-Host "  [ACTION] Service is not running - Attempting to start..." -ForegroundColor Yellow
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-Host "  [SUCCESS] Service started successfully" -ForegroundColor Green
                $actionsTaken += "Started service"
                [Console]::Beep(800, 100)
                [Console]::Beep(1000, 100)
            }
            catch {
                Write-Host "  [ERROR] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
                $actionsTaken += "FAILED to start service"
                
                # Try to get more information
                Write-Host "  [INFO] Checking service dependencies..." -ForegroundColor Cyan
                $dependencies = Get-Service -Name $serviceName | Select-Object -ExpandProperty ServicesDependedOn
                if ($dependencies) {
                    Write-Host "  Dependencies:" -ForegroundColor Cyan
                    foreach ($dep in $dependencies) {
                        Write-Host "    - $($dep.Name): $($dep.Status)" -ForegroundColor Gray
                    }
                }
            }
        }
        
        # Get final status
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $finalStatus = $service.Status
        
        Write-Host "  Final Status: $finalStatus" -ForegroundColor $(if ($finalStatus -eq "Running") { "Green" } else { "Red" })
        
        $results += [PSCustomObject]@{
            Service = $serviceName
            InitialStatus = $initialStatus
            FinalStatus = $finalStatus
            StartupType = $service.StartType
            Action = if ($actionsTaken.Count -gt 0) { $actionsTaken -join ", " } else { "None needed" }
            Result = if ($finalStatus -eq "Running") { "OK" } else { "FAILED" }
        }
    }
    catch {
        Write-Host "  [ERROR] Exception: $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Service = $serviceName
            InitialStatus = "Error"
            FinalStatus = "Error"
            Action = "Exception"
            Result = "ERROR"
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$results | Format-Table -AutoSize

$running = ($results | Where-Object { $_.Result -eq "OK" }).Count
$failed = ($results | Where-Object { $_.Result -eq "FAILED" }).Count
$notFound = ($results | Where-Object { $_.Result -eq "N/A" }).Count

Write-Host "Services Running: $running" -ForegroundColor Green
Write-Host "Services Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "Services Not Found: $notFound" -ForegroundColor Gray

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  SERVICE REPAIR COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Stop-Transcript
Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
Write-Host ""
