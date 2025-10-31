# Real-time Security Event Monitor
# Monitors for suspicious activities and alerts
# Requires Administrator privileges

param(
    [Parameter(Mandatory=$false)]
    [switch]$EnableSound = $false
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$alertLog = "SecurityAlerts_$timestamp.txt"

$trackedProcesses = @{}
$trackedConnections = @{}
$trackedFiles = @{}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  REAL-TIME SECURITY MONITOR" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Monitoring started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[INFO] Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
Write-Host "[INFO] Alerts will be logged to: $alertLog" -ForegroundColor Yellow
Write-Host ""

function Write-Alert {
    param(
        [string]$Message,
        [string]$Severity = "WARNING"
    )
    
    $alertTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $alertMessage = "[$alertTime] [$Severity] $Message"
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Cyan" }
        default { "Yellow" }
    }
    
    Write-Host $alertMessage -ForegroundColor $color
    Add-Content -Path $alertLog -Value $alertMessage
    
    if ($EnableSound -and $Severity -in @("CRITICAL", "HIGH")) {
        [Console]::Beep(1000, 200)
    }
}

$suspiciousProcessNames = @(
    "powershell", "cmd", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "certutil", "bitsadmin", "psexec", "mimikatz",
    "nc", "netcat", "ncat"
)

$suspiciousCommands = @(
    "-encodedcommand", "-enc", "invoke-expression", "iex", "downloadstring",
    "net user", "net localgroup", "reg add", "schtasks", "sc create",
    "wmic", "powershell -w hidden", "bypass", "base64"
)

Write-Alert "Security monitoring initialized" "LOW"

try {
    while ($true) {
        $currentProcesses = Get-Process | Select-Object Name, Id, Path, CommandLine -ErrorAction SilentlyContinue
        
        foreach ($proc in $currentProcesses) {
            if (-not $trackedProcesses.ContainsKey($proc.Id)) {
                $trackedProcesses[$proc.Id] = $true
                
                if ($suspiciousProcessNames -contains $proc.Name.ToLower()) {
                    Write-Alert "Suspicious process started: $($proc.Name) (PID: $($proc.Id)) - Path: $($proc.Path)" "HIGH"
                }
                
                try {
                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    if ($cmdLine) {
                        foreach ($pattern in $suspiciousCommands) {
                            if ($cmdLine -match [regex]::Escape($pattern)) {
                                Write-Alert "SUSPICIOUS COMMAND DETECTED: $($proc.Name) with args containing '$pattern' - Full: $cmdLine" "CRITICAL"
                                break
                            }
                        }
                    }
                }
                catch { }
            }
        }
        
        $currentConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        foreach ($conn in $currentConnections) {
            $connKey = "$($conn.LocalPort)-$($conn.RemoteAddress)-$($conn.RemotePort)"
            
            if (-not $trackedConnections.ContainsKey($connKey)) {
                $trackedConnections[$connKey] = $true
                
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.Name } else { "Unknown" }
                
                if ($conn.RemotePort -in @(4444, 5555, 6666, 7777, 31337, 12345, 1337)) {
                    Write-Alert "Connection to suspicious port: $processName -> $($conn.RemoteAddress):$($conn.RemotePort)" "CRITICAL"
                }
                
                if ($suspiciousProcessNames -contains $processName.ToLower() -and 
                    $conn.RemoteAddress -notmatch "^(127\.|::1|10\.|192\.168\.)") {
                    Write-Alert "External connection from suspicious process: $processName -> $($conn.RemoteAddress):$($conn.RemotePort)" "HIGH"
                }
            }
        }
        
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = (Get-Date).AddSeconds(-10)
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $securityEvents) {
            if ($event.Id -eq 4720) {
                Write-Alert "NEW USER ACCOUNT CREATED: Check Event ID 4720 in Security log" "CRITICAL"
            }
            
            if ($event.Id -eq 4732) {
                Write-Alert "User added to local group: Check Event ID 4732 in Security log" "HIGH"
            }
            
            if ($event.Id -eq 4625) {
                Write-Alert "Failed login attempt detected: Event ID 4625" "MEDIUM"
            }
        }
        
        $systemEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 1,2
            StartTime = (Get-Date).AddSeconds(-10)
        } -MaxEvents 20 -ErrorAction SilentlyContinue
        
        foreach ($event in $systemEvents) {
            if ($event.LevelDisplayName -eq "Error" -or $event.LevelDisplayName -eq "Critical") {
                Write-Alert "System Event: $($event.LevelDisplayName) - $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))..." "MEDIUM"
            }
        }
        
        try {
            $recentTasks = Get-ScheduledTask | Where-Object { 
                $_.Date -gt (Get-Date).AddMinutes(-5) 
            } -ErrorAction SilentlyContinue
            
            foreach ($task in $recentTasks) {
                Write-Alert "New scheduled task created: $($task.TaskName)" "HIGH"
            }
        }
        catch { }
        
        if ($trackedProcesses.Count -gt 1000) {
            $runningPids = (Get-Process).Id
            $trackedProcesses.Keys | Where-Object { $_ -notin $runningPids } | ForEach-Object {
                $trackedProcesses.Remove($_)
            }
        }
        
        if ($trackedConnections.Count -gt 1000) {
            $trackedConnections.Clear()
        }
        
        Start-Sleep -Seconds 2
    }
}
catch {
    Write-Alert "Monitor stopped: $($_.Exception.Message)" "LOW"
}
finally {
    Write-Host "`n[INFO] Monitoring stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "[INFO] Alert log saved to: $alertLog" -ForegroundColor Yellow
}
