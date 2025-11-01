# =========================================
# FIREWALL LOCKDOWN SCRIPT
# =========================================
# Secures firewall with team-specific rules

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
$backupFile = Join-Path $Global:TeamConfig.BackupDirectory "fw-backup-$timestamp.xml"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  FIREWALL LOCKDOWN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Backup current firewall rules
Write-Host "[BACKUP] Exporting current firewall rules..." -ForegroundColor Yellow
Get-NetFirewallRule | Export-Clixml -Path $backupFile
Write-Host "[SUCCESS] Backup saved to: $backupFile" -ForegroundColor Green
Write-Host ""

# Enable firewall for all profiles
Write-Host "[ACTION] Enabling firewall for all profiles..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Host "[SUCCESS] Firewall enabled for all profiles" -ForegroundColor Green
Write-Host ""

# Enable logging
Write-Host "[ACTION] Enabling firewall logging..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 8192
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
Write-Host "[SUCCESS] Firewall logging enabled: $logPath" -ForegroundColor Green
Write-Host ""

# Remove dangerous rules
Write-Host "[ACTION] Removing potentially dangerous rules..." -ForegroundColor Yellow
$removedCount = 0

# Remove rules that allow any remote address on non-scoring ports
$dangerousRules = Get-NetFirewallRule | Where-Object {
    $_.Direction -eq "Inbound" -and 
    $_.Action -eq "Allow" -and 
    $_.Enabled -eq $true
} | ForEach-Object {
    $rule = $_
    $portFilter = $rule | Get-NetFirewallPortFilter
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    
    # Check if rule allows from any address and is not a scoring port
    if ($addressFilter.RemoteAddress -contains "Any" -and $portFilter.LocalPort) {
        $isScoring = $false
        foreach ($port in $portFilter.LocalPort) {
            if ($Global:TeamConfig.ScoringPorts.TCP -contains $port -or 
                $Global:TeamConfig.ScoringPorts.UDP -contains $port) {
                $isScoring = $true
                break
            }
        }
        
        if (-not $isScoring) {
            Write-Host "  [REMOVE] $($rule.DisplayName) - Port: $($portFilter.LocalPort)" -ForegroundColor Red
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            $removedCount++
        }
    }
}

Write-Host "[INFO] Removed $removedCount potentially dangerous rules" -ForegroundColor Cyan
Write-Host ""

# Create whitelist rules for White Team IPs
Write-Host "[ACTION] Creating whitelist rules for White Team/Scoring Engine..." -ForegroundColor Yellow
foreach ($ip in $Global:TeamConfig.WhiteTeamIPs) {
    $ruleName = "CCDC-Whitelist-$ip"
    
    # Remove existing rule if present
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    # Create new rule
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -RemoteAddress $ip `
        -Profile Any `
        -Enabled True `
        -Description "White Team/Scoring Engine - DO NOT REMOVE" | Out-Null
    
    Write-Host "  [ADDED] Whitelist rule for $ip" -ForegroundColor Green
}
Write-Host ""

# Create rules for scoring ports
Write-Host "[ACTION] Creating firewall rules for scoring ports..." -ForegroundColor Yellow

# TCP Ports
foreach ($port in $Global:TeamConfig.ScoringPorts.TCP) {
    $ruleName = "CCDC-Scoring-TCP-$port"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $port `
        -Profile Any `
        -Enabled True `
        -Description "Scoring port - Required for competition" | Out-Null
    
    Write-Host "  [ADDED] TCP port $port (scoring)" -ForegroundColor Green
}

# UDP Ports
foreach ($port in $Global:TeamConfig.ScoringPorts.UDP) {
    $ruleName = "CCDC-Scoring-UDP-$port"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol UDP `
        -LocalPort $port `
        -Profile Any `
        -Enabled True `
        -Description "Scoring port - Required for competition" | Out-Null
    
    Write-Host "  [ADDED] UDP port $port (scoring)" -ForegroundColor Green
}

# ICMP (Ping) for scoring
if ($Global:TeamConfig.ScoringPorts.ICMP) {
    $ruleName = "CCDC-Scoring-ICMP"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol ICMPv4 `
        -IcmpType 8 `
        -Profile Any `
        -Enabled True `
        -Description "ICMP Echo Request (ping) - Required for scoring" | Out-Null
    
    Write-Host "  [ADDED] ICMP (ping) for scoring" -ForegroundColor Green
}

Write-Host ""

# Block common attack ports (that aren't scoring ports)
Write-Host "[ACTION] Blocking common attack ports..." -ForegroundColor Yellow
$attackPorts = @(4444, 4445, 5555, 6666, 7777, 31337, 12345, 1337, 8888, 9999)
foreach ($port in $attackPorts) {
    # Only block if not a scoring port
    if ($Global:TeamConfig.ScoringPorts.TCP -notcontains $port) {
        $ruleName = "CCDC-Block-Attack-$port"
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Action Block `
            -Protocol TCP `
            -LocalPort $port `
            -Profile Any `
            -Enabled True `
            -Description "Block common attack port" | Out-Null
        
        Write-Host "  [BLOCKED] TCP port $port (common attack port)" -ForegroundColor Red
    }
}

Write-Host ""

# Display current status
Write-Host "[INFO] Current Firewall Status:" -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table

Write-Host "[INFO] CCDC Rules Created:" -ForegroundColor Cyan
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "CCDC-*" } | 
    Select-Object DisplayName, Direction, Action, Enabled | Format-Table

Write-Host "========================================" -ForegroundColor Green
Write-Host "  FIREWALL LOCKDOWN COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Firewall backup: $backupFile" -ForegroundColor Cyan
Write-Host "[INFO] Log file: $logPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "[WARNING] Monitor firewall logs for blocked scoring attempts!" -ForegroundColor Yellow
Write-Host ""
