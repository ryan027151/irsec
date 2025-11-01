# =========================================
# TEAM CONFIGURATION FILE
# EDIT THIS WITH YOUR TEAM INFORMATION
# =========================================

# Team Information
$Global:TeamConfig = @{
    TeamNumber = "TEAM-XX"  # CHANGE THIS to your team number
    TeamName = "YourTeamName"  # CHANGE THIS to your team name
    
    # Authorized Users (users that SHOULD exist)
    AuthorizedUsers = @(
        "Administrator",
        "ccdc_admin",
        "team_user1",
        "team_user2"
        # ADD YOUR AUTHORIZED USERS HERE
    )
    
    # Authorized Administrators (users that should have admin rights)
    AuthorizedAdmins = @(
        "Administrator",
        "ccdc_admin"
        # ADD YOUR AUTHORIZED ADMINS HERE
    )
    
    # White Team / Scoring Engine IPs (NEVER BLOCK THESE!)
    WhiteTeamIPs = @(
        "10.0.0.1",      # Scoring engine
        "10.0.0.2",      # White team
        "192.168.1.1"    # Competition infrastructure
        # ADD WHITE TEAM IPs HERE
    )
    
    # Team Network Range (our infrastructure)
    TeamNetworkRange = @(
        "10.X.0.0/16",   # CHANGE THIS to your team's network
        "192.168.X.0/24" # CHANGE THIS to your team's network
    )
    
    # Critical Services to Monitor/Protect
    CriticalServices = @(
        "W3SVC",           # IIS
        "DNS",             # DNS Server
        "LanmanServer",    # SMB/File Sharing
        "WinRM",           # Windows Remote Management
        "Spooler",         # Print Spooler
        "MSSQLSERVER"      # SQL Server (if applicable)
    )
    
    # Required Firewall Ports (for scoring)
    ScoringPorts = @{
        TCP = @(80, 443, 445, 3389, 5985, 5986, 53)  # HTTP, HTTPS, SMB, RDP, WinRM, DNS
        UDP = @(53, 123, 137, 138)                    # DNS, NTP, NetBIOS
        ICMP = $true                                   # Allow ping for scoring
    }
    
    # Monitoring Intervals (in seconds)
    MonitoringIntervals = @{
        NetworkCapture = 30      # Check network every 30 seconds
        ProcessMonitor = 5       # Check processes every 5 seconds
        ServiceCheck = 15        # Check services every 15 seconds
        UserAudit = 60          # Check users every 60 seconds
    }
    
    # Log Directory
    LogDirectory = "C:\CCDC-Logs"
    
    # Backup Directory
    BackupDirectory = "C:\CCDC-Backups"
}

# =========================================
# DO NOT EDIT BELOW THIS LINE
# =========================================

# Create directories if they don't exist
if (-not (Test-Path $Global:TeamConfig.LogDirectory)) {
    New-Item -ItemType Directory -Path $Global:TeamConfig.LogDirectory -Force | Out-Null
}

if (-not (Test-Path $Global:TeamConfig.BackupDirectory)) {
    New-Item -ItemType Directory -Path $Global:TeamConfig.BackupDirectory -Force | Out-Null
}

Write-Host "[CONFIG] Team configuration loaded for $($Global:TeamConfig.TeamName)" -ForegroundColor Green
Write-Host "[CONFIG] Team Number: $($Global:TeamConfig.TeamNumber)" -ForegroundColor Cyan
Write-Host "[CONFIG] Log Directory: $($Global:TeamConfig.LogDirectory)" -ForegroundColor Cyan
Write-Host "[CONFIG] Backup Directory: $($Global:TeamConfig.BackupDirectory)" -ForegroundColor Cyan
