# =========================================
# STARTUP INTEGRITY CHECK
# =========================================
# Checks for suspicious startup programs and persistence

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
$logFile = Join-Path $Global:TeamConfig.LogDirectory "StartupIntegrity_$timestamp.log"
$reportFile = Join-Path $Global:TeamConfig.LogDirectory "StartupIntegrity_$timestamp.csv"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STARTUP INTEGRITY CHECK" -ForegroundColor Cyan
Write-Host "  Team: $($Global:TeamConfig.TeamName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-Transcript -Path $logFile

$allStartupItems = @()

# Check Registry Run keys
Write-Host "[1/5] Checking Registry Run keys..." -ForegroundColor Cyan
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $allStartupItems += [PSCustomObject]@{
                    Location = $key
                    Name = $_.Name
                    Command = $_.Value
                    Type = "Registry Run Key"
                }
                Write-Host "  Found: $($_.Name)" -ForegroundColor Yellow
            }
        }
    }
}

# Check Startup folders
Write-Host ""
Write-Host "[2/5] Checking Startup folders..." -ForegroundColor Cyan
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        $items = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $target = if ($item.Extension -eq ".lnk") {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($item.FullName)
                    $shortcut.TargetPath
                }
                catch { $item.FullName }
            } else { $item.FullName }
            
            $allStartupItems += [PSCustomObject]@{
                Location = $folder
                Name = $item.Name
                Command = $target
                Type = "Startup Folder"
            }
            Write-Host "  Found: $($item.Name)" -ForegroundColor Yellow
        }
    }
}

# Check Scheduled Tasks
Write-Host ""
Write-Host "[3/5] Checking Scheduled Tasks..." -ForegroundColor Cyan
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
foreach ($task in $tasks) {
    $actions = $task.Actions
    foreach ($action in $actions) {
        if ($action.Execute) {
            $allStartupItems += [PSCustomObject]@{
                Location = "Scheduled Task: $($task.TaskPath)"
                Name = $task.TaskName
                Command = "$($action.Execute) $($action.Arguments)"
                Type = "Scheduled Task"
            }
        }
    }
}
Write-Host "  Found: $($tasks.Count) active scheduled tasks" -ForegroundColor Yellow

# Check Services set to automatic
Write-Host ""
Write-Host "[4/5] Checking Automatic Services..." -ForegroundColor Cyan
$services = Get-Service | Where-Object { $_.StartType -eq "Automatic" }
foreach ($service in $services) {
    try {
        $servicePath = (Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue).PathName
        if ($servicePath) {
            $allStartupItems += [PSCustomObject]@{
                Location = "Service"
                Name = $service.Name
                Command = $servicePath
                Type = "Automatic Service"
            }
        }
    }
    catch { }
}
Write-Host "  Found: $($services.Count) automatic services" -ForegroundColor Yellow

# Check WMI Event Subscriptions (advanced persistence)
Write-Host ""
Write-Host "[5/5] Checking WMI Event Subscriptions..." -ForegroundColor Cyan
try {
    $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $wmiBindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    
    if ($wmiBindings) {
        Write-Host "  [WARNING] Found $($wmiBindings.Count) WMI event subscriptions!" -ForegroundColor Red
        foreach ($binding in $wmiBindings) {
            $allStartupItems += [PSCustomObject]@{
                Location = "WMI Event Subscription"
                Name = $binding.__PATH
                Command = "Filter: $($binding.Filter) -> Consumer: $($binding.Consumer)"
                Type = "WMI Persistence"
            }
        }
    } else {
        Write-Host "  No WMI event subscriptions found" -ForegroundColor Green
    }
}
catch {
    Write-Host "  Could not check WMI subscriptions" -ForegroundColor Gray
}

# Analyze for suspicious items
Write-Host ""
Write-Host "[ANALYSIS] Checking for suspicious startup items..." -ForegroundColor Yellow
Write-Host ""

$suspiciousItems = @()

foreach ($item in $allStartupItems) {
    $isSuspicious = $false
    $reasons = @()
    
    # Check for suspicious command patterns
    $suspiciousPatterns = @(
        "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "certutil", "bitsadmin",
        "base64", "encoded", "hidden", "bypass",
        "downloadstring", "iex", "invoke-expression",
        "\\temp\\", "\\appdata\\local\\temp\\", "\\public\\"
    )
    
    foreach ($pattern in $suspiciousPatterns) {
        if ($item.Command -match [regex]::Escape($pattern)) {
            $isSuspicious = $true
            $reasons += "Contains: $pattern"
        }
    }
    
    if ($isSuspicious) {
        $suspiciousItems += $item
        Write-Host "[SUSPICIOUS] $($item.Name)" -ForegroundColor Red
        Write-Host "  Location: $($item.Location)" -ForegroundColor Yellow
        Write-Host "  Command: $($item.Command)" -ForegroundColor Yellow
        Write-Host "  Reasons: $($reasons -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        
        $response = Read-Host "  Remove this startup item? (Y/N)"
        if ($response -eq "Y" -or $response -eq "y") {
            try {
                if ($item.Type -eq "Registry Run Key") {
                    Remove-ItemProperty -Path $item.Location -Name $item.Name -Force
                    Write-Host "  [REMOVED] Registry entry deleted" -ForegroundColor Green
                }
                elseif ($item.Type -eq "Startup Folder") {
                    $filePath = Join-Path $item.Location $item.Name
                    Remove-Item -Path $filePath -Force
                    Write-Host "  [REMOVED] Startup file deleted" -ForegroundColor Green
                }
                elseif ($item.Type -eq "Scheduled Task") {
                    Unregister-ScheduledTask -TaskName $item.Name -Confirm:$false
                    Write-Host "  [REMOVED] Scheduled task deleted" -ForegroundColor Green
                }
                else {
                    Write-Host "  [INFO] Manual removal required for this type" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [ERROR] Failed to remove: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host ""
    }
}

# Export all startup items
$allStartupItems | Export-Csv -Path $reportFile -NoTypeInformation

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total startup items: $($allStartupItems.Count)" -ForegroundColor White
Write-Host "Suspicious items: $($suspiciousItems.Count)" -ForegroundColor $(if ($suspiciousItems.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Full report saved to: $reportFile" -ForegroundColor Cyan
Write-Host ""

Stop-Transcript
Write-Host "[INFO] Log saved to: $logFile" -ForegroundColor Cyan
Write-Host ""
