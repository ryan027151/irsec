# Capture Network Connections (TCPView-like snapshot)
# Requires Administrator privileges

param(
    [Parameter(Mandatory=$false)]
    [int]$SnapshotInterval = 5,
    [Parameter(Mandatory=$false)]
    [int]$SnapshotCount = 10
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "NetworkSnapshots_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  NETWORK CONNECTION MONITOR" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Capturing $SnapshotCount snapshots every $SnapshotInterval seconds" -ForegroundColor Yellow
Write-Host "[INFO] Output directory: $outputDir" -ForegroundColor Yellow
Write-Host ""

$allConnections = @()
$suspiciousConnections = @()

for ($i = 1; $i -le $SnapshotCount; $i++) {
    $snapshotTime = Get-Date -Format "yyyyMMdd_HHmmss"
    Write-Host "[SNAPSHOT $i/$SnapshotCount] Capturing at $(Get-Date -Format 'HH:mm:ss')..." -ForegroundColor Cyan
    
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | ForEach-Object {
        $conn = $_
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        
        [PSCustomObject]@{
            SnapshotNumber = $i
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
    }
    
    $snapshotFile = Join-Path $outputDir "Snapshot_${i}_$snapshotTime.csv"
    $connections | Export-Csv -Path $snapshotFile -NoTypeInformation
    
    $allConnections += $connections
    
    foreach ($conn in $connections) {
        $isSuspicious = $false
        $reason = @()
        
        if ($conn.RemotePort -in @(4444, 5555, 6666, 31337, 12345)) {
            $isSuspicious = $true
            $reason += "Common hacker port"
        }
        
        if ($conn.ProcessName -match "^(powershell|cmd|wscript|cscript|mshta|rundll32)$" -and $conn.RemoteAddress -notmatch "^(127\.|::1|10\.|192\.168\.)") {
            $isSuspicious = $true
            $reason += "Script/System process with external connection"
        }
        
        if ($conn.RemoteAddress -notmatch "^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)") {
            if ($conn.ProcessName -notmatch "^(chrome|firefox|msedge|iexplore|teams|outlook|OneDrive)$") {
                $reason += "External connection from uncommon process"
            }
        }
        
        if ($isSuspicious) {
            $suspiciousConnections += [PSCustomObject]@{
                Timestamp = $conn.Timestamp
                Connection = "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                Process = "$($conn.ProcessName) (PID: $($conn.ProcessID))"
                ProcessPath = $conn.ProcessPath
                Reason = $reason -join "; "
            }
            
            Write-Host "  [ALERT] Suspicious: $($conn.ProcessName) -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Red
        }
    }
    
    Write-Host "  Captured: $($connections.Count) active connections" -ForegroundColor Green
    
    if ($i -lt $SnapshotCount) {
        Start-Sleep -Seconds $SnapshotInterval
    }
}

Write-Host "`n[INFO] Generating summary report..." -ForegroundColor Yellow

$masterFile = Join-Path $outputDir "AllConnections_Master.csv"
$allConnections | Export-Csv -Path $masterFile -NoTypeInformation

if ($suspiciousConnections.Count -gt 0) {
    $suspiciousFile = Join-Path $outputDir "SuspiciousConnections.csv"
    $suspiciousConnections | Export-Csv -Path $suspiciousFile -NoTypeInformation
    Write-Host "[WARNING] Found $($suspiciousConnections.Count) suspicious connections!" -ForegroundColor Red
    Write-Host "          See: $suspiciousFile" -ForegroundColor Red
}

$uniqueProcesses = $allConnections | Select-Object ProcessName, ProcessPath -Unique | Sort-Object ProcessName
$processFile = Join-Path $outputDir "UniqueProcesses.csv"
$uniqueProcesses | Export-Csv -Path $processFile -NoTypeInformation

$uniqueIPs = $allConnections | Select-Object RemoteAddress -Unique | Sort-Object RemoteAddress
$ipFile = Join-Path $outputDir "UniqueRemoteIPs.txt"
$uniqueIPs.RemoteAddress | Out-File -FilePath $ipFile

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Total snapshots: $SnapshotCount" -ForegroundColor White
Write-Host "  Total connections logged: $($allConnections.Count)" -ForegroundColor White
Write-Host "  Unique processes: $($uniqueProcesses.Count)" -ForegroundColor White
Write-Host "  Unique remote IPs: $($uniqueIPs.Count)" -ForegroundColor White
Write-Host "  Suspicious connections: $($suspiciousConnections.Count)" -ForegroundColor $(if ($suspiciousConnections.Count -gt 0) { "Red" } else { "Green" })
Write-Host "`n  All data saved to: $outputDir" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan
