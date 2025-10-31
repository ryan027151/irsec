# =========================================
# CONTINUOUS PROCESS MONITOR
# =========================================
# Monitors for suspicious processes and commands
# Alerts and optionally kills malicious processes

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "ProcessMonitor_$timestamp.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONTINUOUS PROCESS MONITOR" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Monitoring started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[INFO] Check interval: $($Global:TeamConfig.MonitoringIntervals.ProcessMonitor) seconds" -ForegroundColor Yellow
Write-Host "[INFO] Log file: $logFile" -ForegroundColor Yellow
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

# Suspicious process names
$suspiciousProcesses = @(
    "nc", "ncat", "netcat",
    "mimikatz", "psexec", "procdump",
    "meterpreter", "beacon",
    "pwdump", "fgdump", "gsecdump",
    "wce", "hashdump",
    "nmap", "masscan",
    "sqlmap", "nikto", "hydra",
    "cobalt", "empire"
)

# Suspicious command patterns
$suspiciousPatterns = @(
    "-encodedcommand", "-enc", "-e ", "-ec ",
    "invoke-expression", "iex", "invoke-webrequest", "iwr",
    "downloadstring", "downloadfile",
    "net user", "net localgroup administrators",
    "reg add", "reg save",
    "schtasks /create",
    "sc create", "sc config",
    "wmic process call create",
    "powershell -w hidden", "powershell -windowstyle hidden",
    "bypass", "-nop", "-noprofile",
    "base64", "frombase64",
    "mimikatz", "sekurlsa",
    "invoke-mimikatz",
    "reverse", "shell",
    "nc -", "ncat -",
    "/bin/sh", "/bin/bash"
)

$trackedProcesses = @{}

Write-Alert "Process monitoring initialized" "INFO"

try {
    while ($true) {
        $currentProcesses = Get-Process | Select-Object Name, Id, Path, CommandLine -ErrorAction SilentlyContinue
        
        foreach ($proc in $currentProcesses) {
            # New process detected
            if (-not $trackedProcesses.ContainsKey($proc.Id)) {
                $trackedProcesses[$proc.Id] = $true
                $isSuspicious = $false
                $reasons = @()
                
                # Check process name
                if ($suspiciousProcesses -contains $proc.Name.ToLower()) {
                    $isSuspicious = $true
                    $reasons += "Known malicious tool: $($proc.Name)"
                }
                
                # Check if running from suspicious locations
                if ($proc.Path) {
                    $suspiciousLocations = @(
                        "\\AppData\\Local\\Temp",
                        "\\Users\\Public",
                        "\\Windows\\Temp",
                        "\\ProgramData",
                        "\\Downloads"
                    )
                    
                    foreach ($location in $suspiciousLocations) {
                        if ($proc.Path -match [regex]::Escape($location)) {
                            $isSuspicious = $true
                            $reasons += "Running from suspicious location"
                            break
                        }
                    }
                }
                
                # Check command line arguments
                try {
                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    if ($cmdLine) {
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($cmdLine.ToLower() -match [regex]::Escape($pattern.ToLower())) {
                                $isSuspicious = $true
                                $reasons += "Suspicious command: contains '$pattern'"
                                break
                            }
                        }
                    }
                }
                catch { }
                
                # Alert if suspicious
                if ($isSuspicious) {
                    $reasonStr = $reasons -join ", "
                    Write-Alert "SUSPICIOUS PROCESS DETECTED!" "CRITICAL"
                    Write-Host "  Process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Red
                    Write-Host "  Path: $($proc.Path)" -ForegroundColor Red
                    if ($cmdLine) {
                        Write-Host "  Command: $cmdLine" -ForegroundColor Red
                    }
                    Write-Host "  Reasons: $reasonStr" -ForegroundColor Yellow
                    Write-Host ""
                    
                    # Ask user what to do
                    Write-Host "  [K] Kill process" -ForegroundColor Red
                    Write-Host "  [A] Allow and whitelist" -ForegroundColor Green
                    Write-Host "  [I] Ignore this time" -ForegroundColor Yellow
                    $response = Read-Host "  Your choice (K/A/I)"
                    
                    switch ($response.ToUpper()) {
                        "K" {
                            try {
                                Stop-Process -Id $proc.Id -Force
                                Write-Alert "KILLED process: $($proc.Name) (PID: $($proc.Id))" "CRITICAL"
                            }
                            catch {
                                Write-Alert "Failed to kill process: $($_.Exception.Message)" "WARNING"
                            }
                        }
                        "A" {
                            Write-Alert "User whitelisted process: $($proc.Name)" "INFO"
                            # Could add to whitelist file here
                        }
                        "I" {
                            Write-Alert "User ignored alert for: $($proc.Name)" "INFO"
                        }
                        default {
                            Write-Alert "Invalid choice - process allowed to continue" "WARNING"
                        }
                    }
                    Write-Host ""
                }
            }
        }
        
        # Clean up tracking for terminated processes
        if ($trackedProcesses.Count -gt 2000) {
            $runningPids = (Get-Process).Id
            $deadPids = $trackedProcesses.Keys | Where-Object { $_ -notin $runningPids }
            foreach ($pid in $deadPids) {
                $trackedProcesses.Remove($pid)
            }
            Write-Alert "Cleaned up tracking cache (removed $($deadPids.Count) dead processes)" "INFO"
        }
        
        Start-Sleep -Seconds $Global:TeamConfig.MonitoringIntervals.ProcessMonitor
    }
}
catch {
    Write-Alert "Monitor stopped: $($_.Exception.Message)" "WARNING"
}
finally {
    Write-Host ""
    Write-Host "[INFO] Process monitoring stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
}
