
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Script Descriptions](#script-descriptions)
- [Verification Guide](#verification-guide)
- [Troubleshooting](#troubleshooting)


- **Automated Incident Response**: Collects forensic data (network, users, processes, services, logs)
- **Firewall Lockdown**: Configures firewall with team-specific rules and whitelists
- **User Management**: Audits, cleans up unauthorized users, resets passwords
- **PIN/Biometric Removal**: Disables Windows Hello and PINs to prevent bypass
- **Service Protection**: Monitors and auto-restarts critical services
- **Continuous Monitoring**: Real-time detection of suspicious processes and network connections
- **Interactive Alerts**: Prompts for action on detected threats

### Set Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Required Scripts

Ensure you have all of these files:
- `config.ps1` - **CRITICAL: Edit this first!**
- `0-MASTER-CCDC-Response.ps1` - Master orchestration script
- `incident-response.ps1` - Forensic data collection
- `firewall-lockdown.ps1` - Firewall configuration
- `user-cleanup.ps1` - Remove unauthorized users
- `check-users.ps1` - Audit user permissions
- `reset-passwords.ps1` - Reset passwords
- `disable-pins.ps1` - Remove PINs/biometrics
- `service-repair.ps1` - Fix stopped services
- `startup-integrity.ps1` - Check for persistence
- `continuous-network-monitor.ps1` - Network monitoring
- `continuous-process-monitor.ps1` - Process monitoring
- `service-watchdog.ps1` - Service protection

---

Before running ANY scripts, edit `config.ps1` 

```powershell
# Open config.ps1 in notepad
notepad config.ps1
```

**Required Changes:**

1. **Team Information**:
   ```powershell
   TeamNumber = "TEAM-01"  # Your team number
   TeamName = "Blue Team Alpha"  # Your team name
   ```

2. **Authorized Users** (users that SHOULD exist):
   ```powershell
   AuthorizedUsers = @(
       "Administrator",
       "ccdc_admin",
       "john_smith",
       "jane_doe"
   )
   ```

3. **Authorized Admins** (users who should have admin rights):
   ```powershell
   AuthorizedAdmins = @(
       "Administrator",
       "ccdc_admin"
   )
   ```

4. **White Team IPs** (NEVER BLOCK THESE):
   ```powershell
   WhiteTeamIPs = @(
       "10.0.0.1",      # Scoring engine
       "10.0.0.2",      # White team
       "192.168.100.1"  # Competition infra
   )
   ```

5. **Team Network Range**:
   ```powershell
   TeamNetworkRange = @(
       "10.1.0.0/16",      # Your team's network
       "192.168.1.0/24"
   )
   ```

6. **Scoring Ports** (required for competition scoring):
   ```powershell
   ScoringPorts = @{
       TCP = @(80, 443, 445, 3389, 5985, 53)  # HTTP, HTTPS, SMB, RDP, WinRM, DNS
       UDP = @(53, 123, 137, 138)              # DNS, NTP, NetBIOS
       ICMP = $true                             # Allow ping
   }
   ```


```powershell
# Run as Administrator
.\0-MASTER-CCDC-Response.ps1
```
##REMEMBER TO TURN TO LOCAL USER FIRST AND USE PASSWORD (IF NOT LOCAL USER ALREADY)

This will:
1. Collect incident response data
2. Lock down firewall
3. Clean up unauthorized users
4. Reset passwords (with confirmation)
5. Disable PINs
6. Repair critical services
7. Check startup integrity
8. Launch continuous monitors

### Run Individual Scripts

```powershell
# Incident response only
.\incident-response.ps1

# Firewall lockdown only
.\firewall-lockdown.ps1

# User cleanup only
.\user-cleanup.ps1

# Check users only
.\check-users.ps1

# Reset passwords only
.\reset-passwords.ps1

# Disable PINs only
.\disable-pins.ps1

# Service repair only
.\service-repair.ps1

# Startup integrity check only
.\startup-integrity.ps1

# Start network monitor only
.\continuous-network-monitor.ps1

# Start process monitor only
.\continuous-process-monitor.ps1

# Start service watchdog only
.\service-watchdog.ps1
```

### Skip Specific Steps

```powershell
# Skip password reset
.\0-MASTER-CCDC-Response.ps1 -SkipPasswordReset

# Skip firewall configuration
.\0-MASTER-CCDC-Response.ps1 -SkipFirewall

# Skip multiple steps
.\0-MASTER-CCDC-Response.ps1 -SkipPasswordReset -SkipPINDisable
```

---


#### `incident-response.ps1`
Collects comprehensive forensic data:
- System information
- Network configuration (ipconfig, routes, connections)
- Active processes and services
- User accounts and group memberships
- Scheduled tasks
- Event logs (last 24 hours)
- Firewall rules
- DNS/ARP cache
- Network shares

**Output**: `IR-<hostname>-<timestamp>.zip`

#### `firewall-lockdown.ps1`
Secures Windows Firewall:
- Enables firewall for all profiles
- Sets default deny inbound
- Creates whitelist rules for scoring IPs
- Allows only required scoring ports
- Blocks common attack ports (4444, 5555, etc.)
- Enables comprehensive logging

**Output**: Firewall backup in `fw-backup-<timestamp>.xml`

#### `user-cleanup.ps1`
Manages user accounts:
- Identifies unauthorized users
- Prompts to delete or disable
- Removes unauthorized admins
- Checks Remote Desktop Users group
- Interactive confirmation for all changes

#### `check-users.ps1`
Audits user permissions:
- Lists all users and their groups
- Flags unauthorized users
- Highlights unauthorized admins
- Checks for domain users with local admin
- Generates HTML and CSV reports

**Output**: `UserAudit_<timestamp>.html` and `.csv`

#### `reset-passwords.ps1`
Resets user passwords:
- Generates secure random passwords (16 chars)
- Only resets authorized users
- Saves passwords to encrypted log
- Does NOT log you out immediately

**Output**: `PasswordReset_<timestamp>.txt` (CRITICAL - SECURE THIS FILE)

#### `disable-pins.ps1`
Removes PINs and biometrics:
- Disables Windows Hello
- Removes all user PINs
- Clears NGC credentials
- Forces password authentication

#### `service-repair.ps1`
Fixes critical services:
- Checks all services in config
- Sets startup type to Automatic
- Starts stopped services
- Reports on dependencies

#### `startup-integrity.ps1`
Detects persistence mechanisms:
- Scans Registry Run keys
- Checks Startup folders
- Lists Scheduled Tasks
- Identifies suspicious patterns
- Interactive removal of threats

### Continuous Monitoring Scripts

#### `continuous-network-monitor.ps1`
Real-time network monitoring:
- Tracks all TCP connections
- Alerts on suspicious ports
- Detects external connections from system processes
- Periodic snapshots every 30 seconds
- Interactive: Prompts to kill suspicious processes

**Suspicious Indicators**:
- Connections to ports: 4444, 5555, 6666, 31337, etc.
- PowerShell/cmd with external connections
- Unexpected processes connecting outside team network

#### `continuous-process-monitor.ps1`
Real-time process monitoring:
- Detects new processes
- Analyzes command-line arguments
- Identifies known malicious tools
- Checks for suspicious execution paths
- Interactive: Kill, Allow, or Ignore

**Suspicious Patterns**:
- Mimikatz, PSExec, Netcat, etc.
- Base64 encoded commands
- Hidden PowerShell windows
- Downloads from internet
- Lateral movement commands

#### `service-watchdog.ps1`
Automatic service protection:
- Monitors critical services every 15 seconds
- Auto-restarts if stopped
- Re-enables if disabled
- Audible alerts on actions
- Defeats red team service attacks

---
Verifying each script

#### 1. Incident Response Data Collection

```powershell
# Check if ZIP file was created
Get-ChildItem IR-*.zip | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Extract and review
Expand-Archive -Path "IR-*.zip" -DestinationPath ".\IR-Review"
```

#### 2. Firewall Configuration

```powershell
# Check firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Should show:
# - Enabled: True (all profiles)
# - DefaultInboundAction: Block
# - DefaultOutboundAction: Allow

# Check CCDC rules
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "CCDC-*" }

# View firewall log
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 50
```

#### 3. User Accounts

```powershell
# Check password last set dates
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet | Format-Table

# Check administrators
Get-LocalGroupMember -Group "Administrators"

# Open audit report
Invoke-Item (Get-ChildItem UserAudit_*.html | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

#### 4. Password Reset

```powershell
# Find password file (SECURE THIS!)
Get-ChildItem PasswordReset_*.txt | Sort-Object LastWriteTime -Descending

# View passwords (then DELETE file!)
notepad (Get-ChildItem PasswordReset_*.txt | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

#### 5. PINs Disabled

```powershell
# Check Windows Hello status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue

# Should show: Enabled : 0
```

#### 6. Critical Services Running

```powershell
# Check critical services
$services = @("W3SVC", "DNS", "LanmanServer", "WinRM")
Get-Service -Name $services | Select-Object Name, Status, StartType | Format-Table
```

#### 7. Continuous Monitors Active

```powershell
# Check if monitor windows are running
Get-Process powershell | Where-Object { $_.MainWindowTitle -match "network-monitor|process-monitor|watchdog" }
```

### Using Built-in Windows Tools

#### Event Viewer
```powershell
eventvwr.msc
```
- Check **Security** log for Event ID 4724 (password resets)
- Check **System** log for service starts/stops

#### Firewall GUI
```powershell
firewall.cpl
```
- Verify all profiles are ON
- Check inbound rules

#### Local Users and Groups
```powershell
lusrmgr.msc
```
- Verify unauthorized users removed
- Check Administrators group

### Third-Party Tools (Optional)

#### Sysinternals Suite
Download from: https://docs.microsoft.com/en-us/sysinternals/

- **TCPView**: Visual network connections
- **Process Explorer**: Advanced task manager
- **Autoruns**: Startup programs
- **Process Monitor**: System activity logging

#### Commands to Export Current State

```powershell
# Create verification report
$reportPath = "C:\CCDC-Toolkit\Verification-$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

@"
VERIFICATION REPORT
===================
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME

FIREWALL STATUS:
$(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table | Out-String)

LOCAL USERS:
$(Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet | Format-Table | Out-String)

ADMINISTRATORS:
$(Get-LocalGroupMember -Group "Administrators" | Format-Table | Out-String)

CRITICAL SERVICES:
$(Get-Service W3SVC, DNS, LanmanServer, WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table | Out-String)

ACTIVE CONNECTIONS:
$(Get-NetTCPConnection -State Established | Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table | Out-String)
"@ | Out-File -FilePath $reportPath

Write-Host "[SUCCESS] Verification report created: $reportPath" -ForegroundColor Green
```

---


#### "Execution policy error"
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### "config.ps1 not found"
Make sure you're in the correct directory and `config.ps1` exists:
```powershell
cd C:\CCDC-Toolkit
Test-Path .\config.ps1
```

#### "Access denied" errors
Make sure you're running PowerShell as Administrator:
```powershell
# Check if admin
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
```

#### Firewall blocks scoring
Check firewall logs and add missing ports:
```powershell
# View blocked connections
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 100 | Select-String "DROP"

# Add missing port
New-NetFirewallRule -DisplayName "CCDC-Scoring-TCP-<PORT>" -Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT>
```

#### Services won't start
Check dependencies:
```powershell
$service = Get-Service -Name "W3SVC"
$service.ServicesDependedOn | Select-Object Name, Status
```

#### Monitors not detecting threats
Check monitoring intervals in `config.ps1` and verify monitors are running:
```powershell
Get-Process powershell | Where-Object { $_.MainWindowTitle -ne "" }
```

---

### Commands

```powershell
# Quick status check
Get-NetFirewallProfile | Select Name, Enabled
Get-LocalUser | Select Name, Enabled, PasswordLastSet
Get-Service W3SVC, DNS, LanmanServer | Select Name, Status

# View logs
Get-ChildItem C:\CCDC-Logs -Recurse | Sort LastWriteTime -Descending | Select -First 10

# Emergency service restart
Restart-Service -Name W3SVC, DNS, LanmanServer -Force

# Check for unauthorized admins
Get-LocalGroupMember -Group "Administrators"

# View active connections
Get-NetTCPConnection -State Established | Select LocalPort, RemoteAddress, RemotePort, OwningProcess

# Kill suspicious process
Stop-Process -Id <PID> -Force
```
