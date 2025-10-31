# Windows Firewall: IP Whitelisting Guide
## CCDC Competition - Allowing Specific IPs

---

## Table of Contents
1. [Overview](#overview)
2. [Before You Begin](#before-you-begin)
3. [Method 1: PowerShell (Recommended)](#method-1-powershell-recommended)
4. [Method 2: Windows Firewall GUI](#method-2-windows-firewall-gui)
5. [Method 3: Command Line (netsh)](#method-3-command-line-netsh)
6. [Verification](#verification)
7. [Common Scenarios](#common-scenarios)
8. [Troubleshooting](#troubleshooting)

---

## Overview

This guide explains how to whitelist specific IP addresses in Windows Firewall to ensure:
- Scoring engine can reach your services
- White team has administrative access
- Team members can connect
- Red team attacks are blocked

### Key Concepts

**Whitelist** = Allow specific IPs through firewall
**Default Deny** = Block all other traffic

---

## Before You Begin

### Critical IPs to Whitelist

| IP Type | Example | Purpose |
|---------|---------|---------|
| Scoring Engine | 10.0.0.1 | Competition scoring |
| White Team | 10.0.0.2-10 | Competition staff |
| Team Network | 10.X.0.0/16 | Your infrastructure |
| Backup/Monitoring | 192.168.100.50 | Internal services |

**⚠️ WARNING**: Never block White Team or Scoring Engine IPs!

### What You'll Need

- Administrator access
- List of IPs to whitelist
- Port numbers (if specific services)

---

## Method 1: PowerShell (Recommended)

### Step 1: Open PowerShell as Administrator

```powershell
# Right-click Start → Windows PowerShell (Admin)
```

### Step 2: Whitelist a Single IP (All Ports)

```powershell
# Template
New-NetFirewallRule -DisplayName "Whitelist-<Name>" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress <IP_ADDRESS> `
    -Profile Any `
    -Enabled True

# Example: Whitelist scoring engine
New-NetFirewallRule -DisplayName "Whitelist-ScoringEngine" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress 10.0.0.1 `
    -Profile Any `
    -Enabled True
```

### Step 3: Whitelist Multiple IPs

```powershell
# Array of IPs to whitelist
$whitelistIPs = @(
    "10.0.0.1",      # Scoring engine
    "10.0.0.2",      # White team
    "192.168.1.100", # Team member
    "192.168.1.101"  # Team member
)

# Create rules for each IP
foreach ($ip in $whitelistIPs) {
    New-NetFirewallRule -DisplayName "Whitelist-$ip" `
        -Direction Inbound `
        -Action Allow `
        -RemoteAddress $ip `
        -Profile Any `
        -Enabled True
    
    Write-Host "[SUCCESS] Whitelisted: $ip" -ForegroundColor Green
}
```

### Step 4: Whitelist IP Range (CIDR Notation)

```powershell
# Example: Whitelist entire team network 10.1.0.0/16
New-NetFirewallRule -DisplayName "Whitelist-TeamNetwork" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "10.1.0.0/16" `
    -Profile Any `
    -Enabled True
```

### Step 5: Whitelist IP for Specific Port

```powershell
# Example: Allow 10.0.0.1 to access port 80 (HTTP)
New-NetFirewallRule -DisplayName "Whitelist-HTTP-ScoringEngine" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 80 `
    -RemoteAddress "10.0.0.1" `
    -Profile Any `
    -Enabled True
```

### Step 6: Whitelist IP for Multiple Ports

```powershell
# Example: Allow 10.0.0.1 to access HTTP, HTTPS, RDP
$ports = @(80, 443, 3389)
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "Whitelist-TCP$port-ScoringEngine" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $port `
        -RemoteAddress "10.0.0.1" `
        -Profile Any `
        -Enabled True
}
```

### Complete PowerShell Script

```powershell
# ============================================
# WHITELIST IP ADDRESSES - POWERSHELL SCRIPT
# ============================================

# EDIT THESE VALUES
$whitelistIPs = @(
    @{IP="10.0.0.1"; Name="ScoringEngine"; Ports=@(80,443,3389,5985,53)},
    @{IP="10.0.0.2"; Name="WhiteTeam"; Ports=@()},  # Empty = all ports
    @{IP="192.168.1.100"; Name="TeamMember1"; Ports=@(3389)}
)

foreach ($entry in $whitelistIPs) {
    if ($entry.Ports.Count -eq 0) {
        # Whitelist for all ports
        New-NetFirewallRule -DisplayName "Whitelist-$($entry.Name)" `
            -Direction Inbound `
            -Action Allow `
            -RemoteAddress $entry.IP `
            -Profile Any `
            -Enabled True
        Write-Host "[SUCCESS] Whitelisted $($entry.IP) ($($entry.Name)) - All ports" -ForegroundColor Green
    }
    else {
        # Whitelist for specific ports
        foreach ($port in $entry.Ports) {
            New-NetFirewallRule -DisplayName "Whitelist-$($entry.Name)-Port$port" `
                -Direction Inbound `
                -Action Allow `
                -Protocol TCP `
                -LocalPort $port `
                -RemoteAddress $entry.IP `
                -Profile Any `
                -Enabled True
        }
        Write-Host "[SUCCESS] Whitelisted $($entry.IP) ($($entry.Name)) - Ports: $($entry.Ports -join ',')" -ForegroundColor Green
    }
}

Write-Host "`n[INFO] Whitelist rules created successfully!" -ForegroundColor Cyan
```

---

## Method 2: Windows Firewall GUI

### Step 1: Open Windows Firewall

```
1. Press Windows Key + R
2. Type: wf.msc
3. Press Enter
```

### Step 2: Create Inbound Rule

```
1. Click "Inbound Rules" in left pane
2. Click "New Rule..." in right pane
3. Select "Custom" → Next
4. Select "All programs" → Next
5. Protocol: Select protocol (or "Any")
6. Click Next
```

### Step 3: Specify IP Addresses

```
1. Under "Which remote IP addresses...?"
2. Select "These IP addresses"
3. Click "Add..."
4. Enter IP address or range
5. Click OK
6. Click Next
```

### Step 4: Allow the Connection

```
1. Select "Allow the connection"
2. Click Next
```

### Step 5: Apply to All Profiles

```
1. Check all boxes:
   ☑ Domain
   ☑ Private
   ☑ Public
2. Click Next
```

### Step 6: Name the Rule

```
1. Name: "Whitelist-<Description>"
2. Description: "Allow from <IP> for <purpose>"
3. Click Finish
```

---

## Method 3: Command Line (netsh)

### Whitelist Single IP

```cmd
netsh advfirewall firewall add rule name="Whitelist-ScoringEngine" ^
    dir=in action=allow remoteip=10.0.0.1 enable=yes
```

### Whitelist IP Range

```cmd
netsh advfirewall firewall add rule name="Whitelist-TeamNetwork" ^
    dir=in action=allow remoteip=10.1.0.0/16 enable=yes
```

### Whitelist IP for Specific Port

```cmd
netsh advfirewall firewall add rule name="Whitelist-HTTP-Scoring" ^
    dir=in action=allow protocol=TCP localport=80 remoteip=10.0.0.1 enable=yes
```

---

## Verification

### Check if Rule Exists (PowerShell)

```powershell
# List all whitelist rules
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Whitelist-*" } | 
    Select-Object DisplayName, Direction, Action, Enabled

# Check specific IP rule
Get-NetFirewallRule -DisplayName "Whitelist-ScoringEngine" | 
    Get-NetFirewallAddressFilter
```

### Check if Rule Exists (GUI)

```
1. Open wf.msc
2. Click "Inbound Rules"
3. Look for rules starting with "Whitelist-"
4. Double-click to view details
```

### Test Connection from Whitelisted IP

```powershell
# From the whitelisted IP, test connection
Test-NetConnection -ComputerName <YourServerIP> -Port 80

# Should show:
# TcpTestSucceeded : True
```

### Check Firewall Logs

```powershell
# View firewall log
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 50

# Look for ALLOW entries with your whitelisted IP
```

---

## Common Scenarios

### Scenario 1: Whitelist Scoring Engine for All Services

```powershell
# Allow scoring engine full access
New-NetFirewallRule -DisplayName "Whitelist-ScoringEngine-Full" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "10.0.0.1" `
    -Profile Any `
    -Enabled True
```

### Scenario 2: Whitelist Team Network Range

```powershell
# Allow entire team subnet
New-NetFirewallRule -DisplayName "Whitelist-TeamSubnet" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "10.1.0.0/16" `
    -Profile Any `
    -Enabled True
```

### Scenario 3: Whitelist Multiple Scoring IPs for Web Services

```powershell
# Allow multiple IPs to access HTTP/HTTPS
$scoringIPs = @("10.0.0.1", "10.0.0.2", "10.0.0.3")
$ports = @(80, 443)

foreach ($ip in $scoringIPs) {
    foreach ($port in $ports) {
        New-NetFirewallRule -DisplayName "Whitelist-Web-$ip-Port$port" `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $port `
            -RemoteAddress $ip `
            -Profile Any `
            -Enabled True
    }
}
```

### Scenario 4: Temporarily Allow IP (Then Remove)

```powershell
# Create temporary rule
New-NetFirewallRule -DisplayName "Temp-Allow-Troubleshoot" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "192.168.1.50" `
    -Profile Any `
    -Enabled True

# Later, remove it
Remove-NetFirewallRule -DisplayName "Temp-Allow-Troubleshoot"
```

### Scenario 5: Whitelist for Outbound Connections

```powershell
# Allow outbound to specific IP (e.g., update server)
New-NetFirewallRule -DisplayName "Whitelist-Outbound-UpdateServer" `
    -Direction Outbound `
    -Action Allow `
    -RemoteAddress "192.168.100.50" `
    -Profile Any `
    -Enabled True
```

---

## Troubleshooting

### Issue: Scoring Engine Can't Connect

**Check:**
1. Verify scoring IP is whitelisted:
   ```powershell
   Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Scoring*" }
   ```

2. Check firewall is enabled:
   ```powershell
   Get-NetFirewallProfile | Select Name, Enabled
   ```

3. Check firewall logs for blocks:
   ```powershell
   Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | 
       Select-String "DROP" | Select-String "10.0.0.1"
   ```

**Fix:**
```powershell
# Re-create scoring rule
New-NetFirewallRule -DisplayName "Emergency-Scoring-Allow" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "10.0.0.1" `
    -Profile Any `
    -Enabled True
```

### Issue: Rule Exists But Not Working

**Check rule is enabled:**
```powershell
Set-NetFirewallRule -DisplayName "Whitelist-ScoringEngine" -Enabled True
```

**Check rule applies to correct profile:**
```powershell
Set-NetFirewallRule -DisplayName "Whitelist-ScoringEngine" -Profile Any
```

### Issue: Wrong IP Was Whitelisted

**Remove incorrect rule:**
```powershell
Remove-NetFirewallRule -DisplayName "Whitelist-<Name>"
```

**Create correct rule:**
```powershell
New-NetFirewallRule -DisplayName "Whitelist-<Name>" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "<CorrectIP>" `
    -Profile Any `
    -Enabled True
```

### Issue: Need to Whitelist Entire Subnet

```powershell
# Use CIDR notation
New-NetFirewallRule -DisplayName "Whitelist-EntireSubnet" `
    -Direction Inbound `
    -Action Allow `
    -RemoteAddress "10.0.0.0/24" `  # /24 = 256 addresses
    -Profile Any `
    -Enabled True
```

---

## Best Practices

### ✅ DO:
- Whitelist scoring engine and white team IPs immediately
- Use descriptive rule names (`Whitelist-ScoringEngine` not `Rule1`)
- Test connections after creating rules
- Document all whitelisted IPs in your team notes
- Back up firewall rules before making changes:
  ```powershell
  Get-NetFirewallRule | Export-Clixml firewall-backup.xml
  ```

### ❌ DON'T:
- Block scoring engine or white team IPs
- Use overly broad rules (0.0.0.0/0)
- Forget to enable logging
- Remove rules without verifying first
- Whitelist unknown IPs

---

## Quick Reference

### Whitelist Single IP
```powershell
New-NetFirewallRule -DisplayName "Whitelist-<Name>" -Direction Inbound -Action Allow -RemoteAddress <IP> -Profile Any -Enabled True
```

### Whitelist IP Range
```powershell
New-NetFirewallRule -DisplayName "Whitelist-<Name>" -Direction Inbound -Action Allow -RemoteAddress "<IP>/24" -Profile Any -Enabled True
```

### Whitelist for Specific Port
```powershell
New-NetFirewallRule -DisplayName "Whitelist-<Name>" -Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT> -RemoteAddress <IP> -Profile Any -Enabled True
```

### List All Whitelist Rules
```powershell
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Whitelist-*" }
```

### Remove Whitelist Rule
```powershell
Remove-NetFirewallRule -DisplayName "Whitelist-<Name>"
```

### Disable Rule (Keep But Don't Apply)
```powershell
Set-NetFirewallRule -DisplayName "Whitelist-<Name>" -Enabled False
```
