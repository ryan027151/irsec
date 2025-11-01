# =========================================
# SERVICE WATCHDOG
# =========================================
# Continuously monitors critical services
# Automatically restarts if stopped by red team

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "ServiceWatchdog_$timestamp.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SERVICE WATCHDOG" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Monitoring started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[INFO] Check interval: $($Global:TeamConfig.MonitoringIntervals.ServiceCheck) seconds" -ForegroundColor Yellow
Write-Host "[INFO] Log file: $logFile" -ForegroundColor Yellow
Write-Host "[INFO] Watching $($Global:TeamConfig.CriticalServices.Count) critical services" -ForegroundColor Yellow
Write-Host "[INFO] Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
Write-Host ""

function Write-Alert {
    param(
        [string]$Message,
        [string]$Severity = "INFO"
    )
    
    $alertTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $alertMessage = "[$alertTime] [$Severity] $Message"
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $alertMessage -ForegroundColor $color
    Add-Content -Path $logFile -Value $alertMessage
    
    if ($Severity -in @("CRITICAL", "HIGH")) {
        [Console]::Beep(1000, 300)
    }
}

Write-Alert "Service watchdog initialized" "INFO"
Write-Alert "Monitoring services: $($Global:TeamConfig.CriticalServices -join ', ')" "INFO"

try {
    while ($true) {
        foreach ($serviceName in $Global:TeamConfig.CriticalServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                
                if (-not $service) {
                    Write-Alert "Service '$serviceName' not found on this system" "WARNING"
                    continue
                }
                
                # Check if service is stopped
                if ($service.Status -ne "Running") {
                    Write-Alert "CRITICAL: Service '$serviceName' is $($service.Status)!" "CRITICAL"
                    
                    # Check if startup type is disabled
                    if ($service.StartType -eq "Disabled") {
                        Write-Alert "Service '$serviceName' is DISABLED - Re-enabling..." "CRITICAL"
                        Set-Service -Name $serviceName -StartupType Automatic
                        Write-Alert "Service '$serviceName' startup type set to Automatic" "INFO"
                    }
                    
                    # Attempt to start the service
                    Write-Alert "Attempting to start service '$serviceName'..." "INFO"
                    try {
                        Start-Service -Name $serviceName -ErrorAction Stop
                        Write-Alert "Successfully started service '$serviceName'" "INFO"
                        [Console]::Beep(800, 100)
                        [Console]::Beep(1000, 100)
                    }
                    catch {
                        Write-Alert "Failed to start service '$serviceName': $($_.Exception.Message)" "CRITICAL"
                    }
                }
                
                # Check if startup type was changed to disabled
                if ($service.StartType -eq "Disabled" -and $service.Status -eq "Running") {
                    Write-Alert "Service '$serviceName' startup is Disabled but running - fixing..." "WARNING"
                    Set-Service -Name $serviceName -StartupType Automatic
                    Write-Alert "Service '$serviceName' startup type restored to Automatic" "INFO"
                }
            }
            catch {
                Write-Alert "Error checking service '$serviceName': $($_.Exception.Message)" "WARNING"
            }
        }
        
        Start-Sleep -Seconds $Global:TeamConfig.MonitoringIntervals.ServiceCheck
    }
}
catch {
    Write-Alert "Watchdog stopped: $($_.Exception.Message)" "WARNING"
}
finally {
    Write-Host ""
    Write-Host "[INFO] Service watchdog stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
}
