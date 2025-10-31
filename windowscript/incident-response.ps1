# =========================================
# INCIDENT RESPONSE DATA COLLECTION
# =========================================
# Collects forensic data for analysis

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Load config
if (Test-Path ".\config.ps1") { . .\config.ps1 }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME
$outputDir = "IR-$hostname-$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  INCIDENT RESPONSE DATA COLLECTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Collecting forensic data..." -ForegroundColor Yellow
Write-Host "[INFO] Output directory: $outputDir" -ForegroundColor Cyan
Write-Host ""

# System Information
Write-Host "[1/12] Collecting system information..." -ForegroundColor Cyan
systeminfo > "$outputDir\systeminfo.txt"
Get-ComputerInfo | Out-File "$outputDir\computerinfo.txt"

# Hostname
Write-Host "[2/12] Collecting hostname..." -ForegroundColor Cyan
hostname > "$outputDir\hostname.txt"

# Network Configuration
Write-Host "[3/12] Collecting network configuration..." -ForegroundColor Cyan
ipconfig /all > "$outputDir\ipconfig.txt"
Get-NetIPConfiguration | Out-File "$outputDir\netip-config.txt"
Get-NetIPAddress | Export-Csv "$outputDir\ip-addresses.csv" -NoTypeInformation

# Network Connections
Write-Host "[4/12] Collecting active network connections..." -ForegroundColor Cyan
netstat -ano > "$outputDir\netstat.txt"
Get-NetTCPConnection | Export-Csv "$outputDir\tcp-connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Export-Csv "$outputDir\udp-endpoints.csv" -NoTypeInformation

# Routing Table
Write-Host "[5/12] Collecting routing table..." -ForegroundColor Cyan
route print > "$outputDir\routing-table.txt"
Get-NetRoute | Export-Csv "$outputDir\routes.csv" -NoTypeInformation

# Local Users
Write-Host "[6/12] Collecting user accounts..." -ForegroundColor Cyan
Get-LocalUser | Select-Object * | Export-Csv "$outputDir\local-users.csv" -NoTypeInformation
Get-LocalGroup | ForEach-Object {
    $groupName = $_.Name
    Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | 
        Select-Object @{N='Group';E={$groupName}}, * | 
        Export-Csv "$outputDir\group-members.csv" -Append -NoTypeInformation
}
net user > "$outputDir\net-users.txt"

# Services
Write-Host "[7/12] Collecting services..." -ForegroundColor Cyan
Get-Service | Select-Object * | Export-Csv "$outputDir\services.csv" -NoTypeInformation
sc query > "$outputDir\sc-query.txt"

# Running Processes
Write-Host "[8/12] Collecting running processes..." -ForegroundColor Cyan
Get-Process | Select-Object * | Export-Csv "$outputDir\processes.csv" -NoTypeInformation
tasklist /v > "$outputDir\tasklist.txt"

# Scheduled Tasks
Write-Host "[9/12] Collecting scheduled tasks..." -ForegroundColor Cyan
Get-ScheduledTask | Select-Object * | Export-Csv "$outputDir\scheduled-tasks.csv" -NoTypeInformation
schtasks /query /fo LIST /v > "$outputDir\schtasks.txt"

# Startup Programs
Write-Host "[10/12] Collecting startup programs..." -ForegroundColor Cyan
Get-CimInstance Win32_StartupCommand | Select-Object * | Export-Csv "$outputDir\startup-programs.csv" -NoTypeInformation

# Installed Software
Write-Host "[11/12] Collecting installed software..." -ForegroundColor Cyan
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
    Export-Csv "$outputDir\installed-software.csv" -NoTypeInformation

# Event Logs (last 24 hours)
Write-Host "[12/12] Collecting event logs (last 24 hours)..." -ForegroundColor Cyan
$startTime = (Get-Date).AddHours(-24)

try {
    Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startTime} -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        Export-Csv "$outputDir\eventlog-application.csv" -NoTypeInformation
} catch { }

try {
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        Export-Csv "$outputDir\eventlog-system.csv" -NoTypeInformation
} catch { }

try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -ErrorAction SilentlyContinly | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        Export-Csv "$outputDir\eventlog-security.csv" -NoTypeInformation
} catch { }

# Firewall Rules
Write-Host "[BONUS] Collecting firewall configuration..." -ForegroundColor Cyan
Get-NetFirewallProfile | Export-Csv "$outputDir\firewall-profiles.csv" -NoTypeInformation
Get-NetFirewallRule | Export-Csv "$outputDir\firewall-rules.csv" -NoTypeInformation

# DNS Cache
Write-Host "[BONUS] Collecting DNS cache..." -ForegroundColor Cyan
Get-DnsClientCache | Export-Csv "$outputDir\dns-cache.csv" -NoTypeInformation
ipconfig /displaydns > "$outputDir\dns-cache.txt"

# ARP Cache
Write-Host "[BONUS] Collecting ARP cache..." -ForegroundColor Cyan
Get-NetNeighbor | Export-Csv "$outputDir\arp-cache.csv" -NoTypeInformation
arp -a > "$outputDir\arp.txt"

# Shares
Write-Host "[BONUS] Collecting network shares..." -ForegroundColor Cyan
Get-SmbShare | Export-Csv "$outputDir\smb-shares.csv" -NoTypeInformation
net share > "$outputDir\net-shares.txt"

# Create summary report
Write-Host ""
Write-Host "[INFO] Generating summary report..." -ForegroundColor Yellow

$summary = @"
INCIDENT RESPONSE SUMMARY
=========================
Hostname: $hostname
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Team: $($Global:TeamConfig.TeamName)
Team Number: $($Global:TeamConfig.TeamNumber)

DATA COLLECTED:
- System Information
- Network Configuration (ipconfig, routes, connections)
- User Accounts and Group Memberships
- Running Services
- Active Processes
- Scheduled Tasks
- Startup Programs
- Installed Software
- Event Logs (Application, System, Security - Last 24h)
- Firewall Configuration
- DNS Cache
- ARP Cache
- Network Shares

FILES LOCATION: $outputDir\

Next Steps:
1. Review all CSV files for anomalies
2. Check for unauthorized users in local-users.csv
3. Review network connections in tcp-connections.csv
4. Examine scheduled tasks for persistence mechanisms
5. Analyze event logs for security events
"@

$summary | Out-File "$outputDir\SUMMARY.txt"

# Compress everything
Write-Host "[INFO] Compressing data package..." -ForegroundColor Yellow
$zipFile = "IR-$hostname-$timestamp.zip"
Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  DATA COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[SUCCESS] Incident response package created:" -ForegroundColor Green
Write-Host "  Location: $zipFile" -ForegroundColor Cyan
Write-Host "  Size: $([math]::Round((Get-Item $zipFile).Length / 1MB, 2)) MB" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Raw data directory: $outputDir" -ForegroundColor Yellow
Write-Host ""
