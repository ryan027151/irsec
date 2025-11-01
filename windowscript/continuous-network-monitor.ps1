# =========================================
# CONTINUOUS NETWORK CONNECTION MONITOR
# =========================================
# Monitors network connections in real-time
# Alerts on suspicious connections
# Periodically captures snapshots

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "NetworkMonitor_$timestamp.log"
$snapshotDir = Join-Path $Global:TeamConfig.LogDirectory "NetworkSnapshots_$timestamp"
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONTINUOUS NETWORK MONITOR" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Monitoring started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[INFO] Check interval: $($Global:TeamConfig.MonitoringIntervals.NetworkCapture) seconds" -ForegroundColor Yellow
Write-Host "[INFO] Log file: $logFile" -ForegroundColor Yellow
Write-Host "[INFO] Snapshots: $snapshotDir" -ForegroundColor Yellow
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

function Test-IPWhitelisted {
    param([string]$IP)
    
    # Check if IP is in whitelist
    foreach ($whiteIP in $Global:TeamConfig.WhiteTeamIPs) {
        if ($IP -eq $whiteIP) {
            return $true
        }
    }
    
    # Check if IP is in team network range
    foreach ($range in $Global:TeamConfig.TeamNetworkRange) {
        # Simple check - could be enhanced with proper CIDR checking
        if ($IP -match "^10\." -or $IP -match "^192\.168\.") {
            return $true
        }
    }
    
    # Localhost always whitelisted
    if ($IP -match "^127\." -or $IP -eq "::1") {
        return $true
    }
    
    return $false
}

$trackedConnections = @{}
$snapshotCounter = 0
$lastSnapshot = Get-Date

Write-Alert "Network monitoring initialized" "INFO"

try {
    while ($true) {
        $currentTime = Get-Date
        
        # Get current connections
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        foreach ($conn in $connections) {
            $connKey = "$($conn.LocalPort)-$($conn.RemoteAddress)-$($conn.RemotePort)-$($conn.OwningProcess)"
            
            # New connection detected
            if (-not $trackedConnections.ContainsKey($connKey)) {
                $trackedConnections[$connKey] = $true
                
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.Name } else { "Unknown" }
                $processPath = if ($process) { $process.Path } else { "Unknown" }
                
                # Check if connection is suspicious
                $isSuspicious = $false
                $reasons = @()
                
                # Check for suspicious ports
                $suspiciousPorts = @(4444, 4445, 5555, 6666, 7777, 31337, 12345, 1337, 8888, 9999)
                if ($conn.RemotePort -in $suspiciousPorts) {
                    $isSuspicious = $true
                    $reasons += "Suspicious port: $($conn.RemotePort)"
                }
                
                # Check for external connections from system processes
                $systemProcesses = @("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil")
                if ($processName.ToLower() -in $systemProcesses -and -not (Test-IPWhitelisted $conn.RemoteAddress)) {
                    $isSuspicious = $true
                    $reasons += "System process with external connection"
                }
                
                # Check for non-whitelisted external connections
                if (-not (Test-IPWhitelisted $conn.RemoteAddress)) {
                    # Connection to internet from unexpected process
                    $expectedBrowsers = @("chrome", "firefox", "msedge", "iexplore", "brave", "opera")
                    if ($processName.ToLower() -notin $expectedBrowsers) {
                        $reasons += "External connection from: $processName"
                    }
                }
                
                # Alert if suspicious
                if ($isSuspicious) {
                    $reasonStr = $reasons -join ", "
                    Write-Alert "SUSPICIOUS CONNECTION: $processName ($($conn.OwningProcess)) -> $($conn.RemoteAddress):$($conn.RemotePort) | Reason: $reasonStr" "HIGH"
                    Write-Host "  Process Path: $processPath" -ForegroundColor Gray
                    
                    # Ask user if they want to kill the process
                    $response = Read-Host "  Kill this process? (Y/N)"
                    if ($response -eq "Y" -or $response -eq "y") {
                        try {
                            Stop-Process -Id $conn.OwningProcess -Force
                            Write-Alert "KILLED process $processName (PID: $($conn.OwningProcess))" "CRITICAL"
                        }
                        catch {
                            Write-Alert "Failed to kill process: $($_.Exception.Message)" "WARNING"
                        }
                    } else {
                        Write-Alert "User allowed process $processName to continue" "INFO"
                    }
                } else {
                    # Log normal connections (less verbosely)
                    if (-not (Test-IPWhitelisted $conn.RemoteAddress)) {
                        Write-Alert "New connection: $processName -> $($conn.RemoteAddress):$($conn.RemotePort)" "INFO"
                    }
                }
            }
        }
        
        # Periodic snapshot
        if (($currentTime - $lastSnapshot).TotalSeconds -ge $Global:TeamConfig.MonitoringIntervals.NetworkCapture) {
            $snapshotCounter++
            $snapshotFile = Join-Path $snapshotDir "Snapshot_$snapshotCounter.csv"
            
            $connections | ForEach-Object {
                $conn = $_
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    ProcessName = if ($process) { $process.Name } else { "Unknown" }
                    ProcessID = $conn.OwningProcess
                    ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                }
            } | Export-Csv -Path $snapshotFile -NoTypeInformation
            
            Write-Alert "Snapshot #$snapshotCounter saved ($($connections.Count) connections)" "INFO"
            $lastSnapshot = $currentTime
        }
        
        # Clean up old tracked connections
        if ($trackedConnections.Count -gt 1000) {
            $trackedConnections.Clear()
            Write-Alert "Cleared connection tracking cache" "INFO"
        }
        
        Start-Sleep -Seconds 2
    }
}
catch {
    Write-Alert "Monitor stopped: $($_.Exception.Message)" "WARNING"
}
finally {
    Write-Host ""
    Write-Host "[INFO] Network monitoring stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "[INFO] Total snapshots: $snapshotCounter" -ForegroundColor Cyan
    Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
}
