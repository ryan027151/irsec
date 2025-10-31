# Script
#!/bin/bash
################################################################################
# COMPLETE IRSeC COMPETITION SCRIPT COLLECTION - LINUX
################################################################################
# Organize these into separate files in your competition toolkit
# Directory structure:
# /toolkit/
#   /phase1_initial/
#   /phase2_continuous/
#   /phase3_incident/
#   /service_specific/
#   /utilities/
################################################################################

################################################################################
# PHASE 1: INITIAL DEPLOYMENT (First 5 Minutes)
################################################################################

################################################################################
# File: phase1_initial/01_enum.sh
# Purpose: Rapid system enumeration - RUN THIS FIRST
# Usage: ./01_enum.sh
################################################################################
#!/bin/bash

echo "==================================="
echo "SYSTEM ENUMERATION - $(date)"
echo "==================================="

OUTPUT="enum_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== BASIC SYSTEM INFO ==="
echo "Hostname: $(hostname)"
echo "Date: $(date)"
echo "Uptime: $(uptime)"
uname -a
cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null

echo -e "\n=== CURRENT USER ==="
whoami
id
groups

echo -e "\n=== ALL USERS ==="
cat /etc/passwd | column -t -s:

echo -e "\n=== SUDO USERS ==="
grep -Po '^sudo.+:\K.*$' /etc/group 2>/dev/null
getent group sudo 2>/dev/null
getent group wheel 2>/dev/null
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"

echo -e "\n=== USERS WITH BASH SHELLS ==="
grep "/bash" /etc/passwd

echo -e "\n=== RECENTLY CREATED USERS (last 7 days) ==="
awk -F: '{print $1,$3}' /etc/passwd | while read user uid; do
    if [ -d "/home/$user" ]; then
        created=$(stat -c %w /home/$user 2>/dev/null || echo "unknown")
        echo "$user (UID: $uid) - Home created: $created"
    fi
done

echo -e "\n=== NETWORK INTERFACES ==="
ip addr show
ifconfig 2>/dev/null

echo -e "\n=== LISTENING PORTS ==="
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

echo -e "\n=== ESTABLISHED CONNECTIONS ==="
ss -tupn 2>/dev/null | grep ESTAB || netstat -tupn 2>/dev/null | grep ESTABLISHED

echo -e "\n=== ROUTING TABLE ==="
ip route
route -n 2>/dev/null

echo -e "\n=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null

echo -e "\n=== ENABLED SERVICES ==="
systemctl list-unit-files --type=service --state=enabled 2>/dev/null

echo -e "\n=== FIREWALL STATUS ==="
ufw status verbose 2>/dev/null
iptables -L -n -v 2>/dev/null
firewall-cmd --list-all 2>/dev/null

echo -e "\n=== CRON JOBS ==="
echo "Root crontab:"
crontab -l 2>/dev/null
echo -e "\nSystem crontab:"
cat /etc/crontab 2>/dev/null
echo -e "\nCron directories:"
ls -la /etc/cron.* 2>/dev/null

echo -e "\n=== SCHEDULED TASKS (systemd timers) ==="
systemctl list-timers --all 2>/dev/null

echo -e "\n=== WORLD WRITABLE DIRECTORIES ==="
find / -type d -perm -0002 -ls 2>/dev/null | head -20

echo -e "\n=== SUID BINARIES ==="
find / -perm -4000 -type f 2>/dev/null

echo -e "\n=== DISK USAGE ==="
df -h

echo -e "\n=== MOUNTED FILESYSTEMS ==="
mount | column -t

echo -e "\n=== RUNNING PROCESSES (top 20) ==="
ps auxf | head -20

echo -e "\n=== WEB SERVER CHECK ==="
if systemctl is-active --quiet apache2; then
    echo "Apache2 is running"
    apache2 -v 2>/dev/null
    ls -la /etc/apache2/ 2>/dev/null
    ls -la /var/www/ 2>/dev/null
elif systemctl is-active --quiet nginx; then
    echo "Nginx is running"
    nginx -v 2>/dev/null
    ls -la /etc/nginx/ 2>/dev/null
    ls -la /var/www/ 2>/dev/null
fi

echo -e "\n=== DATABASE CHECK ==="
if systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb; then
    echo "MySQL/MariaDB is running"
    mysql --version 2>/dev/null
fi
if systemctl is-active --quiet postgresql; then
    echo "PostgreSQL is running"
    psql --version 2>/dev/null
fi

echo -e "\n=== SSH CONFIGURATION ==="
grep -v "^#" /etc/ssh/sshd_config 2>/dev/null | grep -v "^$"

echo -e "\n=== LAST LOGINS ==="
last -20

echo -e "\n=== FAILED LOGIN ATTEMPTS ==="
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20
grep "Failed password" /var/log/secure 2>/dev/null | tail -20

} > "$OUTPUT"

echo "Enumeration complete! Results saved to: $OUTPUT"
cat "$OUTPUT" | less

################################################################################
# File: phase1_initial/02_quick_harden.sh
# Purpose: Immediate system hardening
# Usage: sudo ./02_quick_harden.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "QUICK HARDENING - $(date)"
echo "========================================="

# Create backup directory
BACKUP_DIR="/root/backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "[+] Backup directory: $BACKUP_DIR"

# Backup critical files
echo "[+] Backing up critical configuration files..."
cp /etc/passwd "$BACKUP_DIR/"
cp /etc/shadow "$BACKUP_DIR/"
cp /etc/group "$BACKUP_DIR/"
cp /etc/sudoers "$BACKUP_DIR/"
cp /etc/ssh/sshd_config "$BACKUP_DIR/"
cp /etc/crontab "$BACKUP_DIR/"
[ -d /etc/apache2 ] && cp -r /etc/apache2 "$BACKUP_DIR/"
[ -d /etc/nginx ] && cp -r /etc/nginx "$BACKUP_DIR/"

# Enable and configure firewall
echo "[+] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    # Add more ports as needed for your services
    ufw reload
    echo "UFW firewall enabled"
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --set-default-zone=public
    firewall-cmd --zone=public --add-service=ssh --permanent
    firewall-cmd --zone=public --add-service=http --permanent
    firewall-cmd --zone=public --add-service=https --permanent
    firewall-cmd --reload
    echo "Firewalld enabled"
else
    # Fallback to iptables
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    echo "Basic iptables rules applied"
fi

# Harden SSH
echo "[+] Hardening SSH configuration..."
sed -i.bak 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config

# Restart SSH
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
echo "SSH hardened and restarted"

# Enable audit logging
echo "[+] Enabling audit logging..."
if command -v auditd &> /dev/null; then
    systemctl enable auditd
    systemctl start auditd
    echo "Auditd enabled"
fi

# Disable unnecessary services
echo "[+] Disabling risky services..."
RISKY_SERVICES=("telnet" "rsh" "rlogin" "vsftpd" "pure-ftpd" "proftpd")
for service in "${RISKY_SERVICES[@]}"; do
    systemctl disable "$service" 2>/dev/null
    systemctl stop "$service" 2>/dev/null
done

# Set password policies
echo "[+] Configuring password policies..."
sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Enable password quality requirements (if pam_pwquality is available)
if [ -f /etc/security/pwquality.conf ]; then
    sed -i.bak 's/^# minlen.*/minlen = 12/' /etc/security/pwquality.conf
    sed -i 's/^# dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
    echo "Password quality requirements set"
fi

# Disable IPv6 (optional, if not needed)
# echo "[+] Disabling IPv6..."
# echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
# echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
# sysctl -p

# Enable SYN cookie protection
echo "[+] Enabling SYN flood protection..."
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=5

# Disable IP forwarding (if not a router)
echo "[+] Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0

# Enable exec-shield
sysctl -w kernel.exec-shield=1 2>/dev/null
sysctl -w kernel.randomize_va_space=2 2>/dev/null

# Set secure file permissions
echo "[+] Setting secure permissions on sensitive files..."
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow 2>/dev/null
chmod 600 /etc/ssh/sshd_config

# Check for and remove common backdoor accounts
echo "[+] Checking for suspicious accounts..."
SUSPICIOUS=("backdoor" "hacker" "test" "guest" "admin")
for user in "${SUSPICIOUS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "[!] FOUND SUSPICIOUS USER: $user"
        # Uncomment to automatically delete:
        # userdel -r "$user" 2>/dev/null
    fi
done

echo "========================================="
echo "QUICK HARDENING COMPLETE"
echo "Backups stored in: $BACKUP_DIR"
echo "========================================="

################################################################################
# File: phase1_initial/03_rotate_passwords.sh
# Purpose: Change all user passwords immediately
# Usage: sudo ./03_rotate_passwords.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "PASSWORD ROTATION - $(date)"
echo "========================================="

# IMPORTANT: Change this to your competition password
NEW_PASSWORD="Comp3titi0n!P@ssw0rd2024"

# Get list of human users (UID >= 1000, has shell)
USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ && $1 != "nobody" {print $1}' /etc/passwd)

echo "Rotating passwords for users..."
for user in $USERS; do
    echo "$user:$NEW_PASSWORD" | chpasswd
    if [ $? -eq 0 ]; then
        echo "[+] Password changed for: $user"
    else
        echo "[!] Failed to change password for: $user"
    fi
done

# Change root password
echo "root:$NEW_PASSWORD" | chpasswd
if [ $? -eq 0 ]; then
    echo "[+] Root password changed"
else
    echo "[!] Failed to change root password"
fi

# Optionally force password change on next login
# Uncomment if you want users to change passwords themselves
# for user in $USERS; do
#     passwd -e "$user"
#     echo "[+] Password expiry set for: $user"
# done

# Log password changes
echo "$(date): Passwords rotated for all users" >> /root/password_changes.log

echo "========================================="
echo "PASSWORD ROTATION COMPLETE"
echo "New password: $NEW_PASSWORD"
echo "SAVE THIS SECURELY AND SHARE WITH TEAM"
echo "========================================="

# Display the password prominently
echo ""
echo "**********************************"
echo "NEW PASSWORD: $NEW_PASSWORD"
echo "**********************************"
echo ""

################################################################################
# File: phase1_initial/04_user_audit.sh
# Purpose: Find and document unauthorized users
# Usage: sudo ./04_user_audit.sh
################################################################################
#!/bin/bash

echo "========================================="
echo "USER AUDIT - $(date)"
echo "========================================="

# CRITICAL: Edit this list with YOUR authorized users
AUTHORIZED_USERS=("root" "ubuntu" "debian" "centos" "admin" "yourteam1" "yourteam2")

OUTPUT="user_audit_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== USER AUDIT REPORT ==="
echo "Date: $(date)"
echo ""

echo "=== CHECKING FOR UNAUTHORIZED USERS ==="
ALL_USERS=$(awk -F: '{print $1}' /etc/passwd)
FOUND_UNAUTHORIZED=0

for user in $ALL_USERS; do
    IS_AUTHORIZED=0
    for auth_user in "${AUTHORIZED_USERS[@]}"; do
        if [ "$user" == "$auth_user" ]; then
            IS_AUTHORIZED=1
            break
        fi
    done
    
    if [ $IS_AUTHORIZED -eq 0 ]; then
        # Check if it's a system account (UID < 1000)
        UID=$(id -u "$user" 2>/dev/null)
        if [ $UID -ge 1000 ]; then
            echo "[!] UNAUTHORIZED USER: $user (UID: $UID)"
            echo "    Shell: $(grep "^$user:" /etc/passwd | cut -d: -f7)"
            echo "    Home: $(grep "^$user:" /etc/passwd | cut -d: -f6)"
            echo "    Groups: $(groups "$user" 2>/dev/null)"
            echo "    Last login: $(lastlog -u "$user" 2>/dev/null | tail -1)"
            echo "    To remove: userdel -r $user"
            echo ""
            FOUND_UNAUTHORIZED=$((FOUND_UNAUTHORIZED + 1))
        fi
    fi
done

if [ $FOUND_UNAUTHORIZED -eq 0 ]; then
    echo "[+] No unauthorized users found"
fi

echo ""
echo "=== SUDO GROUP MEMBERS ==="
getent group sudo 2>/dev/null | cut -d: -f4
getent group wheel 2>/dev/null | cut -d: -f4
getent group admin 2>/dev/null | cut -d: -f4

echo ""
echo "=== USERS WITH UID 0 (ROOT PRIVILEGES) ==="
awk -F: '$3 == 0 {print $1 " (DANGER - Has UID 0)"}' /etc/passwd

echo ""
echo "=== USERS WITH EMPTY PASSWORDS ==="
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null

echo ""
echo "=== USERS WITH NO PASSWORD EXPIRY ==="
while IFS=: read -r user _ _ _ max _; do
    if [ "$max" == "99999" ] && id "$user" &>/dev/null; then
        UID=$(id -u "$user")
        if [ $UID -ge 1000 ]; then
            echo "$user (needs password expiry)"
        fi
    fi
done < /etc/shadow 2>/dev/null

echo ""
echo "=== SUDOERS FILE ENTRIES ==="
grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$"

echo ""
echo "=== SSH AUTHORIZED KEYS ==="
for home in /home/* /root; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "Keys for $(basename $home):"
        cat "$home/.ssh/authorized_keys" 2>/dev/null
        echo ""
    fi
done

} | tee "$OUTPUT"

echo "========================================="
echo "USER AUDIT COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="

################################################################################
# PHASE 2: CONTINUOUS OPERATIONS (Throughout Competition)
################################################################################

################################################################################
# File: phase2_continuous/05_monitor.sh
# Purpose: Continuous system monitoring - run in background
# Usage: sudo ./05_monitor.sh &
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

LOGFILE="/root/monitor_$(date +%Y%m%d_%H%M%S).log"
ALERT_FILE="/root/ALERTS.txt"
BASELINE_USERS="/tmp/baseline_users.txt"
BASELINE_CRON="/tmp/baseline_cron.txt"
BASELINE_PROCS="/tmp/baseline_procs.txt"

echo "========================================="
echo "CONTINUOUS MONITORING STARTED"
echo "Log file: $LOGFILE"
echo "Alert file: $ALERT_FILE"
echo "Press Ctrl+C to stop"
echo "========================================="

# Create baselines
cat /etc/passwd > "$BASELINE_USERS"
crontab -l 2>/dev/null > "$BASELINE_CRON"
ps aux > "$BASELINE_PROCS"

while true; do
    echo "=== Monitor Check: $(date) ===" >> "$LOGFILE"
    
    # Check for new users
    if ! diff -q /etc/passwd "$BASELINE_USERS" &>/dev/null; then
        echo "[ALERT] $(date): USER CHANGE DETECTED" | tee -a "$ALERT_FILE"
        diff /etc/passwd "$BASELINE_USERS" >> "$ALERT_FILE"
        cat /etc/passwd > "$BASELINE_USERS"
    fi
    
    # Check for cron changes
    crontab -l 2>/dev/null > /tmp/current_cron.txt
    if ! diff -q /tmp/current_cron.txt "$BASELINE_CRON" &>/dev/null; then
        echo "[ALERT] $(date): CRON JOB CHANGE" | tee -a "$ALERT_FILE"
        diff /tmp/current_cron.txt "$BASELINE_CRON" >> "$ALERT_FILE"
        cp /tmp/current_cron.txt "$BASELINE_CRON"
    fi
    
    # Check active connections
    CONNECTIONS=$(ss -tupn 2>/dev/null | grep ESTAB | wc -l)
    echo "Active connections: $CONNECTIONS" >> "$LOGFILE"
    ss -tupn 2>/dev/null | grep ESTAB >> "$LOGFILE"
    
    # Check for suspicious processes
    ps aux | grep -E 'nc|ncat|netcat|/bin/sh -i|/bin/bash -i|perl.*socket|python.*socket' | grep -v grep >> "$LOGFILE"
    
    # Check listening ports
    echo "Listening ports:" >> "$LOGFILE"
    ss -tulpn 2>/dev/null >> "$LOGFILE"
    
    # Check for unauthorized sudo usage
    grep "sudo:" /var/log/auth.log 2>/dev/null | tail -5 >> "$LOGFILE"
    
    # Check disk usage (ransomware indicator)
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ $DISK_USAGE -gt 90 ]; then
        echo "[ALERT] $(date): DISK USAGE HIGH: $DISK_USAGE%" | tee -a "$ALERT_FILE"
    fi
    
    echo "---" >> "$LOGFILE"
    
    # Check if alert file has new content
    if [ -f "$ALERT_FILE" ] && [ $(wc -l < "$ALERT_FILE") -gt 0 ]; then
        echo -e "\n!!! CHECK $ALERT_FILE FOR ALERTS !!!\n"
    fi
    
    sleep 60
done

################################################################################
# File: phase2_continuous/06_threat_hunt.sh
# Purpose: Active threat hunting - run periodically
# Usage: sudo ./06_threat_hunt.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

OUTPUT="threat_hunt_$(date +%Y%m%d_%H%M%S).txt"

echo "========================================="
echo "THREAT HUNTING - $(date)"
echo "========================================="

{
echo "=== THREAT HUNT REPORT ==="
echo "Date: $(date)"
echo ""

echo "=== SUSPICIOUS CRON JOBS ==="
echo "Root crontab:"
crontab -l 2>/dev/null
echo ""
echo "System crontab:"
cat /etc/crontab
echo ""
echo "Cron directories:"
for dir in /etc/cron.* ; do
    echo "$dir:"
    ls -la "$dir" 2>/dev/null
done

echo -e "\n=== SUSPICIOUS SCHEDULED TASKS (systemd) ==="
systemctl list-timers --all

echo -e "\n=== CHECKING FOR REVERSE SHELLS ==="
ps aux | grep -E 'nc|ncat|netcat|/bin/sh -i|/bin/bash -i|perl.*socket|python.*socket|ruby.*socket' | grep -v grep

echo -e "\n=== SUSPICIOUS NETWORK CONNECTIONS ==="
echo "Established connections to unusual ports:"
ss -tupn | grep ESTAB | grep -v ":22\|:80\|:443\|:53"

echo -e "\n=== LISTENING ON UNUSUAL PORTS ==="
ss -tulpn | grep LISTEN | grep -v ":22\|:80\|:443\|:53\|:3306\|:5432"

echo -e "\n=== SUID BINARIES (potential privilege escalation) ==="
find / -perm -4000 -type f 2>/dev/null | grep -v "/bin/\|/usr/bin/\|/sbin/\|/usr/sbin/"

echo -e "\n=== SGID BINARIES ==="
find / -perm -2000 -type f 2>/dev/null | grep -v "/bin/\|/usr/bin/\|/sbin/\|/usr/sbin/"

echo -e "\n=== WORLD-WRITABLE FILES IN SYSTEM DIRECTORIES ==="
find /etc /usr /bin /sbin -type f -perm -0002 2>/dev/null

echo -e "\n=== RECENTLY MODIFIED FILES IN /etc (last 24 hours) ==="
find /etc -type f -mtime -1 -ls 2>/dev/null

echo -e "\n=== RECENTLY MODIFIED SUID/SGID FILES ==="
find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -7 -ls 2>/dev/null

echo -e "\n=== HIDDEN FILES IN TEMP DIRECTORIES ==="
find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null

echo -e "\n=== SUSPICIOUS PROCESSES ==="
ps aux --sort=-%cpu | head -20

echo -e "\n=== PROCESSES RUNNING AS ROOT ==="
ps aux | grep "^root" | grep -v "\[" | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

echo -e "\n=== CHECKING /tmp FOR EXECUTABLES ==="
find /tmp /var/tmp /dev/shm -type f -executable -ls 2>/dev/null

echo -e "\n=== CHECKING FOR BACKDOOR USERS ==="
awk -F: '$3 == 0 {print $1 " has UID 0!"}' /etc/passwd
grep ":0:" /etc/passwd

echo -e "\n=== SSH AUTHORIZED KEYS ==="
for home in /home/* /root; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "=== $home/.ssh/authorized_keys ==="
        cat "$home/.ssh/authorized_keys" 2>/dev/null
        echo ""
    fi
done

echo -e "\n=== BASH HISTORY (potential recon) ==="
for home in /home/* /root; do
    if [ -f "$home/.bash_history" ]; then
        echo "=== $home/.bash_history (last 20 lines) ==="
        tail -20 "$home/.bash_history" 2>/dev/null
        echo ""
    fi
done

echo -e "\n=== CHECKING FOR WEB SHELLS ==="
if [ -d /var/www ]; then
    echo "Checking /var/www for suspicious PHP files..."
    find /var/www -name "*.php" -type f -exec grep -l "eval\|base64_decode\|system\|exec\|shell_exec\|passthru\|popen\|proc_open" {} \; 2>/dev/null
fi

if [ -d /usr/share/nginx ]; then
    echo "Checking nginx directories..."
    find /usr/share/nginx -name "*.php" -type f -exec grep -l "eval\|base64_decode\|system\|exec" {} \; 2>/dev/null
fi

echo -e "\n=== CHECKING FOR SUSPICIOUS APACHE/NGINX MODULES ==="
if command -v apache2 &>/dev/null; then
    apache2ctl -M 2>/dev/null
elif command -v httpd &>/dev/null; then
    httpd -M 2>/dev/null
fi

echo -e "\n=== KERNEL MODULES (potential rootkits) ==="
lsmod | head -20

echo -e "\n=== CHECKING /dev FOR SUSPICIOUS FILES ==="
find /dev -type f 2>/dev/null

echo -e "\n=== IMMUTABLE FILES (might be rootkit protection) ==="
lsattr /bin/* /usr/bin/* /sbin/* /usr/sbin/* 2>/dev/null | grep "^....i"

echo -e "\n=== CHECKING FOR STARTUP SCRIPTS ==="
ls -la /etc/init.d/ 2>/dev/null
ls -la /etc/rc*.d/ 2>/dev/null | grep -v "README"
systemctl list-unit-files --type=service | grep enabled

echo -e "\n=== CHECKING LD_PRELOAD (library injection) ==="
cat /etc/ld.so.preload 2>/dev/null
echo "Environment LD_PRELOAD:"
env | grep LD_PRELOAD

} | tee "$OUTPUT"

echo "========================================="
echo "THREAT HUNT COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="

# Count findings
WEB_SHELLS=$(grep -c "web shell\|eval\|base64_decode" "$OUTPUT" 2>/dev/null || echo "0")
SUSPICIOUS_PROCS=$(grep -c "nc\|ncat\|netcat\|/bin/sh -i" "$OUTPUT" 2>/dev/null || echo "0")

echo ""
echo "=== SUMMARY ==="
echo "Potential web shells: $WEB_SHELLS"
echo "Suspicious processes: $SUSPICIOUS_PROCS"
echo ""

################################################################################
# File: phase2_continuous/07_log_analyzer.sh
# Purpose: Analyze logs for attack patterns
# Usage: ./07_log_analyzer.sh [logfile]
################################################################################
#!/bin/bash

LOGFILE="${1:-/var/log/auth.log}"

if [ ! -f "$LOGFILE" ]; then
    echo "Log file not found: $LOGFILE"
    echo "Usage: $0 [logfile]"
    exit 1
fi

echo "========================================="
echo "LOG ANALYSIS - $(date)"
echo "Analyzing: $LOGFILE"
echo "========================================="

OUTPUT="log_analysis_$(basename $LOGFILE)_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== LOG ANALYSIS REPORT ==="
echo "File: $LOGFILE"
echo "Date: $(date)"
echo ""

echo "=== FAILED LOGIN ATTEMPTS ==="
grep -i "failed password" "$LOGFILE" | tail -50

echo -e "\n=== FAILED LOGIN SUMMARY BY IP ==="
grep -i "failed password" "$LOGFILE" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -rn | head -20

echo -e "\n=== SUCCESSFUL LOGINS ==="
grep -i "accepted password\|accepted publickey" "$LOGFILE" | tail -30

echo -e "\n=== ROOT LOGIN ATTEMPTS ==="
grep -i "root" "$LOGFILE" | grep -i "failed\|accepted" | tail -30

echo -e "\n=== SUDO USAGE ==="
grep -i "sudo:" "$LOGFILE" | tail -30

echo -e "\n=== USER CREATION/DELETION ==="
grep -iE "useradd|userdel|adduser" "$LOGFILE"

echo -e "\n=== PRIVILEGE ESCALATION ATTEMPTS ==="
grep -i "su:" "$LOGFILE" | tail -20

echo -e "\n=== SSH KEY USAGE ==="
grep -i "publickey" "$LOGFILE" | tail -20

echo -e "\n=== INVALID USERS ==="
grep -i "invalid user" "$LOGFILE" | tail -30

echo -e "\n=== BREAK-IN ATTEMPTS ==="
grep -i "break-in attempt\|possible break-in" "$LOGFILE"

echo -e "\n=== SESSION OPENED/CLOSED ==="
grep -i "session opened\|session closed" "$LOGFILE" | tail -20

} | tee "$OUTPUT"

# Web log analysis (if Apache/Nginx logs exist)
if [ -f /var/log/apache2/access.log ] || [ -f /var/log/nginx/access.log ]; then
    echo -e "\n=== WEB LOG ANALYSIS ==="
    
    WEBLOG="/var/log/apache2/access.log"
    [ -f /var/log/nginx/access.log ] && WEBLOG="/var/log/nginx/access.log"
    
    {
    echo -e "\n=== TOP 20 IPs ==="
    awk '{print $1}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    echo -e "\n=== SQL INJECTION ATTEMPTS ==="
    grep -iE "union.*select|concat.*\(|script.*>|<script|'; drop|' or '1'='1" "$WEBLOG" | tail -30
    
    echo -e "\n=== DIRECTORY TRAVERSAL ATTEMPTS ==="
    grep -E "\.\./|\.\.%2[fF]" "$WEBLOG" | tail -20
    
    echo -e "\n=== SUSPICIOUS USER AGENTS ==="
    grep -iE "nikto|nmap|sqlmap|burp|metasploit|nessus|masscan|acunetix" "$WEBLOG" | tail -20
    
    echo -e "\n=== FILE UPLOAD ATTEMPTS ==="
    grep -iE "\.php|\.asp|\.jsp|\.cgi" "$WEBLOG" | grep POST | tail -20
    
    echo -e "\n=== 404 ERRORS (recon) ==="
    awk '$9 == 404 {print $7}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    echo -e "\n=== 500 ERRORS (exploitation?) ==="
    awk '$9 ~ /^5/ {print $7}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    } | tee -a "$OUTPUT"
fi

echo "========================================="
echo "LOG ANALYSIS COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="

################################################################################
# PHASE 3: INCIDENT RESPONSE (When Attacks Detected)
################################################################################

################################################################################
# File: phase3_incident/08_log_incident.sh
# Purpose: Document incidents with system state capture
# Usage: sudo ./08_log_incident.sh
################################################################################
#!/bin/bash

INCIDENT_LOG="/root/incidents.txt"
INCIDENT_DIR="/root/incidents"
mkdir -p "$INCIDENT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INCIDENT_FILE="$INCIDENT_DIR/incident_$TIMESTAMP.txt"

echo "========================================="
echo "INCIDENT LOGGER"
echo "========================================="

{
echo "========================================="
echo "INCIDENT REPORT"
echo "Timestamp: $(date)"
echo "========================================="

read -p "Incident Title/Summary: " title
echo "Title: $title"

read -p "Severity (Low/Medium/High/Critical): " severity
echo "Severity: $severity"

read -p "Affected System/Service: " affected
echo "Affected: $affected"

read -p "Description of incident: " description
echo "Description: $description"

read -p "Attack vector (if known): " vector
echo "Attack Vector: $vector"

read -p "Actions taken: " actions
echo "Actions Taken: $actions"

echo ""
echo "=== SYSTEM STATE CAPTURE ==="
echo "Captured at: $(date)"

echo -e "\n=== Current Users ==="
who

echo -e "\n=== User Accounts ==="
cat /etc/passwd

echo -e "\n=== Active Processes (top 30) ==="
ps auxf | head -30

echo -e "\n=== Network Connections ==="
ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null

echo -e "\n=== Listening Ports ==="
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

echo -e "\n=== Recent Auth Log Entries ==="
tail -50 /var/log/auth.log 2>/dev/null || tail -50 /var/log/secure 2>/dev/null

echo -e "\n=== Cron Jobs ==="
crontab -l 2>/dev/null

echo -e "\n=== Recent Commands (bash history) ==="
history | tail -50

echo -e "\n=== Disk Usage ==="
df -h

echo -e "\n=== Memory Usage ==="
free -h

echo -e "\n=== Load Average ==="
uptime

echo ""
echo "========================================="
echo "END INCIDENT REPORT"
echo "========================================="

} | tee "$INCIDENT_FILE"

# Also append to master incident log
echo "" >> "$INCIDENT_LOG"
cat "$INCIDENT_FILE" >> "$INCIDENT_LOG"

echo ""
echo "Incident logged to:"
echo "  - $INCIDENT_FILE"
echo "  - $INCIDENT_LOG"
echo ""

################################################################################
# File: phase3_incident/09_capture_evidence.sh
# Purpose: Capture forensic evidence during active incident
# Usage: sudo ./09_capture_evidence.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

EVIDENCE_DIR="/root/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "========================================="
echo "EVIDENCE COLLECTION - $(date)"
echo "Evidence directory: $EVIDENCE_DIR"
echo "========================================="

# Memory dump (if possible)
echo "[+] Capturing running processes..."
ps auxf > "$EVIDENCE_DIR/processes.txt"
pstree -p > "$EVIDENCE_DIR/process_tree.txt"

# Network state
echo "[+] Capturing network state..."
ss -tupn > "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null || netstat -tupn > "$EVIDENCE_DIR/network_connections.txt"
ss -tulpn > "$EVIDENCE_DIR/listening_ports.txt" 2>/dev/null || netstat -tulpn > "$EVIDENCE_DIR/listening_ports.txt"
ip addr > "$EVIDENCE_DIR/ip_addresses.txt"
ip route > "$EVIDENCE_DIR/routing_table.txt"
arp -a > "$EVIDENCE_DIR/arp_cache.txt" 2>/dev/null

# User state
echo "[+] Capturing user information..."
cp /etc/passwd "$EVIDENCE_DIR/"
cp /etc/shadow "$EVIDENCE_DIR/" 2>/dev/null
cp /etc/group "$EVIDENCE_DIR/"
who > "$EVIDENCE_DIR/logged_in_users.txt"
w > "$EVIDENCE_DIR/user_activity.txt"
last -50 > "$EVIDENCE_DIR/last_logins.txt"
lastlog > "$EVIDENCE_DIR/last_log.txt"

# Copy critical logs
echo "[+] Copying log files..."
mkdir -p "$EVIDENCE_DIR/logs"
cp /var/log/auth.log* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/secure* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/syslog* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/messages* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp -r /var/log/apache2 "$EVIDENCE_DIR/logs/" 2>/dev/null
cp -r /var/log/nginx "$EVIDENCE_DIR/logs/" 2>/dev/null

# Scheduled tasks
echo "[+] Capturing scheduled tasks..."
crontab -l > "$EVIDENCE_DIR/root_crontab.txt" 2>/dev/null
cp /etc/crontab "$EVIDENCE_DIR/" 2>/dev/null
ls -laR /etc/cron.* > "$EVIDENCE_DIR/cron_directories.txt" 2>/dev/null
systemctl list-timers --all > "$EVIDENCE_DIR/systemd_timers.txt" 2>/dev/null

# File system
echo "[+] Capturing file system information..."
df -h > "$EVIDENCE_DIR/disk_usage.txt"
mount > "$EVIDENCE_DIR/mounted_filesystems.txt"
find / -type f -mtime -1 2>/dev/null > "$EVIDENCE_DIR/recently_modified_files.txt"
find / -type f -perm -4000 2>/dev/null > "$EVIDENCE_DIR/suid_files.txt"

# Services
echo "[+] Capturing service information..."
systemctl list-units --type=service > "$EVIDENCE_DIR/services.txt" 2>/dev/null
service --status-all > "$EVIDENCE_DIR/services_status.txt" 2>/dev/null

# Kernel modules
echo "[+] Capturing kernel modules..."
lsmod > "$EVIDENCE_DIR/kernel_modules.txt"

# Environment
echo "[+] Capturing environment..."
env > "$EVIDENCE_DIR/environment.txt"

# Capture bash histories
echo "[+] Capturing command histories..."
mkdir -p "$EVIDENCE_DIR/histories"
for home in /home/* /root; do
    if [ -f "$home/.bash_history" ]; then
        cp "$home/.bash_history" "$EVIDENCE_DIR/histories/$(basename $home)_bash_history" 2>/dev/null
    fi
done

# Package information
echo "[+] Capturing package information..."
dpkg -l > "$EVIDENCE_DIR/installed_packages.txt" 2>/dev/null || rpm -qa > "$EVIDENCE_DIR/installed_packages.txt" 2>/dev/null

# Create evidence manifest
echo "[+] Creating manifest..."
{
    echo "Evidence Collection Report"
    echo "Collected: $(date)"
    echo "Hostname: $(hostname)"
    echo "Collected by: $(whoami)"
    echo ""
    echo "Files collected:"
    find "$EVIDENCE_DIR" -type f -exec ls -lh {} \;
} > "$EVIDENCE_DIR/MANIFEST.txt"

# Create tarball
echo "[+] Creating evidence archive..."
tar czf "${EVIDENCE_DIR}.tar.gz" "$EVIDENCE_DIR" 2>/dev/null

echo "========================================="
echo "EVIDENCE COLLECTION COMPLETE"
echo "Directory: $EVIDENCE_DIR"
echo "Archive: ${EVIDENCE_DIR}.tar.gz"
echo "========================================="

################################################################################
# File: phase3_incident/10_kill_backdoor.sh
# Purpose: Remove common backdoor mechanisms
# Usage: sudo ./10_kill_backdoor.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "BACKDOOR REMOVAL - $(date)"
echo "========================================="

LOG="backdoor_removal_$(date +%Y%m%d_%H%M%S).log"

{
echo "=== BACKDOOR REMOVAL LOG ==="
echo "Date: $(date)"

# Kill suspicious processes
echo -e "\n[+] Killing suspicious processes..."
SUSPICIOUS_PROCS=$(ps aux | grep -E 'nc|ncat|/bin/sh -i|/bin/bash -i|perl.*socket|python.*socket' | grep -v grep | awk '{print $2}')
if [ -n "$SUSPICIOUS_PROCS" ]; then
    for pid in $SUSPICIOUS_PROCS; do
        PROC_INFO=$(ps -p $pid -o pid,user,cmd)
        echo "Killing PID $pid: $PROC_INFO"
        kill -9 $pid
    done
else
    echo "No suspicious processes found"
fi

# Check and clean cron jobs
echo -e "\n[+] Checking cron jobs..."
echo "Current root crontab:"
crontab -l 2>/dev/null
read -p "Remove all root cron jobs? (y/N): " remove_cron
if [ "$remove_cron" == "y" ]; then
    crontab -r
    echo "Root crontab cleared"
fi

# Remove suspicious SSH keys
echo -e "\n[+] Checking SSH authorized keys..."
for home in /home/* /root; do
    AUTHKEYS="$home/.ssh/authorized_keys"
    if [ -f "$AUTHKEYS" ]; then
        echo "Keys in $AUTHKEYS:"
        cat "$AUTHKEYS"
        read -p "Remove suspicious keys from $AUTHKEYS? (y/N): " remove_keys
        if [ "$remove_keys" == "y" ]; then
            read -p "Enter line numbers to remove (comma-separated): " lines
            # This is interactive - consider backing up first
            cp "$AUTHKEYS" "${AUTHKEYS}.bak"
            echo "Backup created: ${AUTHKEYS}.bak"
        fi
    fi
done

# Check for backdoor users
echo -e "\n[+] Checking for backdoor users..."
echo "Users with UID >= 1000:"
awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd
read -p "Enter username to delete (or press Enter to skip): " del_user
if [ -n "$del_user" ]; then
    userdel -r "$del_user" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "User $del_user deleted"
    else
        echo "Failed to delete $del_user"
    fi
fi

# Remove web shells
echo -e "\n[+] Searching for web shells in /var/www..."
if [ -d /var/www ]; then
    find /var/www -name "*.php" -type f -exec grep -l "eval\|base64_decode\|system\|exec\|shell_exec" {} \; 2>/dev/null | while read file; do
        echo "Suspicious file: $file"
        read -p "Delete $file? (y/N): " del_file
        if [ "$del_file" == "y" ]; then
            rm "$file"
            echo "Deleted: $file"
        fi
    done
fi

# Check for suspicious startup scripts
echo -e "\n[+] Checking startup scripts..."
systemctl list-unit-files --type=service | grep enabled | grep -v "^systemd\|^dbus\|^getty"

# Remove suspicious kernel modules
echo -e "\n[+] Current kernel modules:"
lsmod | head -20
read -p "Enter module name to remove (or press Enter to skip): " rmmod_name
if [ -n "$rmmod_name" ]; then
    rmmod "$rmmod_name" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Module $rmmod_name removed"
    else
        echo "Failed to remove $rmmod_name"
    fi
fi

echo -e "\n=== BACKDOOR REMOVAL COMPLETE ==="

} | tee "$LOG"

echo "Log saved to: $LOG"

################################################################################
# PHASE 4: SERVICE-SPECIFIC SCRIPTS
################################################################################

################################################################################
# File: service_specific/11_harden_apache.sh
# Purpose: Harden Apache web server
# Usage: sudo ./11_harden_apache.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v apache2 &>/dev/null && ! command -v httpd &>/dev/null; then
    echo "Apache not found"
    exit 1
fi

echo "========================================="
echo "APACHE HARDENING - $(date)"
echo "========================================="

# Determine Apache binary and config
if command -v apache2 &>/dev/null; then
    APACHE_BIN="apache2"
    APACHE_CONF="/etc/apache2/apache2.conf"
    APACHE_DIR="/etc/apache2"
    SITES_DIR="/etc/apache2/sites-available"
else
    APACHE_BIN="httpd"
    APACHE_CONF="/etc/httpd/conf/httpd.conf"
    APACHE_DIR="/etc/httpd"
    SITES_DIR="/etc/httpd/conf.d"
fi

# Backup configuration
BACKUP_DIR="/root/apache_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r "$APACHE_DIR" "$BACKUP_DIR/"
echo "[+] Backup created: $BACKUP_DIR"

# Remove default pages
echo "[+] Removing default pages..."
rm -f /var/www/html/index.html 2>/dev/null
rm -f /var/www/html/index.nginx-debian.html 2>/dev/null
echo "Apache2 Secured" > /var/www/html/index.html

# Create security.conf
SECURITY_CONF="$APACHE_DIR/conf-available/security-custom.conf"
if [ -d "$APACHE_DIR/conf-available" ]; then
    echo "[+] Creating security configuration..."
    cat > "$SECURITY_CONF" << 'EOF'
# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable directory listing
<Directory /var/www/>
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

# Disable unnecessary HTTP methods
<Location />
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Location>

# Clickjacking protection
Header always append X-Frame-Options SAMEORIGIN

# XSS Protection
Header set X-XSS-Protection "1; mode=block"

# Prevent MIME sniffing
Header set X-Content-Type-Options nosniff

# Disable ETags
FileETag None

# Timeout settings
Timeout 60
KeepAliveTimeout 5

# Limit request size (10MB)
LimitRequestBody 10485760
EOF

    # Enable the configuration
    if command -v a2enconf &>/dev/null; then
        a2enconf security-custom
    fi
fi

# Set proper permissions
echo "[+] Setting secure file permissions..."
find /var/www -type d -exec chmod 755 {} \;
find /var/www -type f -exec chmod 644 {} \;
chown -R www-data:www-data /var/www 2>/dev/null || chown -R apache:apache /var/www 2>/dev/null

# Disable unnecessary modules
echo "[+] Disabling unnecessary modules..."
DISABLE_MODS="autoindex status userdir"
for mod in $DISABLE_MODS; do
    a2dismod $mod 2>/dev/null
done

# Enable security modules
echo "[+] Enabling security modules..."
ENABLE_MODS="headers rewrite ssl"
for mod in $ENABLE_MODS; do
    a2enmod $mod 2>/dev/null
done

# Test configuration
echo "[+] Testing Apache configuration..."
$APACHE_BIN -t

# Restart Apache
read -p "Restart Apache now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null
    echo "[+] Apache restarted"
fi

echo "========================================="
echo "APACHE HARDENING COMPLETE"
echo "========================================="

################################################################################
# File: service_specific/12_harden_mysql.sh
# Purpose: Harden MySQL/MariaDB database
# Usage: sudo ./12_harden_mysql.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "MYSQL/MARIADB HARDENING - $(date)"
echo "========================================="

# Check if MySQL is installed
if ! command -v mysql &>/dev/null; then
    echo "MySQL/MariaDB not found"
    exit 1
fi

echo "[!] This script will ask for the current MySQL root password"
read -sp "Enter current MySQL root password: " CURRENT_PASS
echo ""
read -sp "Enter NEW MySQL root password: " NEW_PASS
echo ""

# Test connection
if ! mysql -uroot -p"$CURRENT_PASS" -e "SELECT 1;" &>/dev/null; then
    echo "[!] Failed to connect to MySQL. Check password."
    exit 1
fi

echo "[+] Connected to MySQL successfully"

# Run hardening SQL commands
mysql -uroot -p"$CURRENT_PASS" << EOF
-- Change root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_PASS';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Drop test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Remove users without passwords
DELETE FROM mysql.user WHERE authentication_string='';

-- Flush privileges
FLUSH PRIVILEGES;

-- Show remaining users
SELECT User, Host FROM mysql.user;
EOF

echo "[+] MySQL security hardening applied"

# Secure my.cnf
echo "[+] Hardening MySQL configuration file..."
MY_CNF="/etc/mysql/my.cnf"
[ -f /etc/my.cnf ] && MY_CNF="/etc/my.cnf"

# Backup config
cp "$MY_CNF" "${MY_CNF}.backup.$(date +%Y%m%d_%H%M%S)"

# Add security settings (if not already present)
if ! grep -q "bind-address.*127.0.0.1" "$MY_CNF"; then
    cat >> "$MY_CNF" << 'EOF'

[mysqld]
# Bind to localhost only
bind-address = 127.0.0.1

# Disable LOAD DATA LOCAL INFILE
local-infile=0

# Enable logging
general_log = 1
general_log_file = /var/log/mysql/mysql.log
log_error = /var/log/mysql/error.log

# Disable symbolic links
symbolic-links=0
EOF
fi

echo "[+] MySQL configuration hardened"

# Set secure file permissions
chmod 644 "$MY_CNF"

# Restart MySQL
read -p "Restart MySQL now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null
    echo "[+] MySQL restarted"
fi

echo "========================================="
echo "MYSQL HARDENING COMPLETE"
echo "New root password: $NEW_PASS"
echo "========================================="

################################################################################
# File: service_specific/13_harden_ssh.sh
# Purpose: Advanced SSH hardening
# Usage: sudo ./13_harden_ssh.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "SSH HARDENING - $(date)"
echo "========================================="

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original config
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
echo "[+] Backup created"

# Apply hardening
echo "[+] Applying SSH hardening..."

# Function to set or replace config value
set_config() {
    local key="$1"
    local value="$2"
    if grep -q "^#*${key}" "$SSHD_CONFIG"; then
        sed -i "s/^#*${key}.*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# Apply all hardening settings
set_config "PermitRootLogin" "no"
set_config "PasswordAuthentication" "yes"
set_config "PermitEmptyPasswords" "no"
set_config "X11Forwarding" "no"
set_config "MaxAuthTries" "3"
set_config "ClientAliveInterval" "300"
set_config "ClientAliveCountMax" "2"
set_config "Protocol" "2"
set_config "LogLevel" "VERBOSE"
set_config "MaxSessions" "2"
set_config "TCPKeepAlive" "no"
set_config "AllowTcpForwarding" "no"
set_config "AllowAgentForwarding" "no"
set_config "PermitUserEnvironment" "no"

# Strong ciphers and MACs
if ! grep -q "^Ciphers" "$SSHD_CONFIG"; then
    cat >> "$SSHD_CONFIG" << 'EOF'

# Strong ciphers only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF
fi

# Test configuration
echo "[+] Testing SSH configuration..."
sshd -t
if [ $? -ne 0 ]; then
    echo "[!] SSH configuration test failed! Restoring backup..."
    cp "${SSHD_CONFIG}.backup."* "$SSHD_CONFIG"
    exit 1
fi

# Restart SSH
read -p "Restart SSH now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo "[+] SSH restarted"
fi

echo "========================================="
echo "SSH HARDENING COMPLETE"
echo "========================================="

################################################################################
# File: service_specific/14_harden_dns.sh
# Purpose: Harden BIND DNS server
# Usage: sudo ./14_harden_dns.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v named &>/dev/null; then
    echo "BIND DNS server not found"
    exit 1
fi

echo "========================================="
echo "DNS (BIND) HARDENING - $(date)"
echo "========================================="

NAMED_CONF="/etc/bind/named.conf.options"
[ -f /etc/named.conf ] && NAMED_CONF="/etc/named.conf"

# Backup config
cp "$NAMED_CONF" "${NAMED_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
echo "[+] Backup created"

# Create hardened configuration
cat >> "$NAMED_CONF" << 'EOF'

// Security options
options {
    // Restrict zone transfers
    allow-transfer { none; };
    
    // Disable recursion for external queries
    recursion no;
    
    // Rate limiting
    rate-limit {
        responses-per-second 10;
        window 5;
    };
    
    // Hide version
    version "Not Available";
    
    // Enable query logging
    querylog yes;
    
    // Disable notify
    notify no;
};
EOF

echo "[+] DNS hardening configuration added"

# Test configuration
named-checkconf
if [ $? -ne 0 ]; then
    echo "[!] Configuration test failed"
    exit 1
fi

# Restart DNS
read -p "Restart BIND now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
    echo "[+] BIND restarted"
fi

echo "========================================="
echo "DNS HARDENING COMPLETE"
echo "========================================="

################################################################################
# File: service_specific/15_harden_nginx.sh
# Purpose: Harden Nginx web server
# Usage: sudo ./15_harden_nginx.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v nginx &>/dev/null; then
    echo "Nginx not found"
    exit 1
fi

echo "========================================="
echo "NGINX HARDENING - $(date)"
echo "========================================="

NGINX_CONF="/etc/nginx/nginx.conf"
BACKUP_DIR="/root/nginx_backup_$(date +%Y%m%d_%H%M%S)"

# Backup configuration
mkdir -p "$BACKUP_DIR"
cp -r /etc/nginx "$BACKUP_DIR/"
echo "[+] Backup created: $BACKUP_DIR"

# Remove default pages
echo "[+] Removing default pages..."
rm -f /var/www/html/index.nginx-debian.html 2>/dev/null
echo "Nginx Secured" > /var/www/html/index.html

# Create security configuration
SECURITY_CONF="/etc/nginx/conf.d/security.conf"
echo "[+] Creating security configuration..."
cat > "$SECURITY_CONF" << 'EOF'
# Hide Nginx version
server_tokens off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_req_status 429;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 10;

# Buffer overflow protection
client_body_buffer_size 1K;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 2 1k;

# Timeouts
client_body_timeout 10;
client_header_timeout 10;
keepalive_timeout 5 5;
send_timeout 10;
EOF

# Set proper permissions
echo "[+] Setting secure file permissions..."
find /var/www -type d -exec chmod 755 {} \;
find /var/www -type f -exec chmod 644 {} \;
chown -R www-data:www-data /var/www 2>/dev/null

# Test configuration
echo "[+] Testing Nginx configuration..."
nginx -t

if [ $? -ne 0 ]; then
    echo "[!] Configuration test failed!"
    exit 1
fi

# Restart Nginx
read -p "Restart Nginx now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart nginx
    echo "[+] Nginx restarted"
fi

echo "========================================="
echo "NGINX HARDENING COMPLETE"
echo "========================================="

################################################################################
# UTILITY SCRIPTS
################################################################################

################################################################################
# File: utilities/16_quick_check.sh
# Purpose: Quick security status check
# Usage: sudo ./16_quick_check.sh
################################################################################
#!/bin/bash

echo "========================================="
echo "QUICK SECURITY CHECK - $(date)"
echo "========================================="

# Check firewall
echo "[Firewall Status]"
if command -v ufw &>/dev/null; then
    ufw status | head -5
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --state
else
    echo "Checking iptables..."
    iptables -L -n | head -10
fi

# Check for root/sudo users
echo -e "\n[Privileged Users]"
echo "Root equivalent users (UID 0):"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo "Sudo group members:"
getent group sudo 2>/dev/null | cut -d: -f4
getent group wheel 2>/dev/null | cut -d: -f4

# Check active connections
echo -e "\n[Active Network Connections]"
ss -tupn 2>/dev/null | grep ESTAB | wc -l || netstat -tupn 2>/dev/null | grep ESTABLISHED | wc -l
echo "connections active"

# Check suspicious processes
echo -e "\n[Suspicious Processes]"
ps aux | grep -E 'nc |ncat|netcat|/bin/sh -i|/bin/bash -i' | grep -v grep

# Check last logins
echo -e "\n[Recent Logins]"
last -5

# Check cron jobs
echo -e "\n[Cron Jobs]"
echo "Root crontab lines:"
crontab -l 2>/dev/null | wc -l

# Check listening ports
echo -e "\n[Listening Ports]"
ss -tulpn 2>/dev/null | grep LISTEN | awk '{print $5}' | sort -u || netstat -tulpn 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u

echo "========================================="

################################################################################
# File: utilities/17_find_webshells.sh
# Purpose: Scan for web shells
# Usage: sudo ./17_find_webshells.sh [directory]
################################################################################
#!/bin/bash

SCAN_DIR="${1:-/var/www}"

if [ ! -d "$SCAN_DIR" ]; then
    echo "Directory not found: $SCAN_DIR"
    exit 1
fi

echo "========================================="
echo "WEB SHELL SCANNER - $(date)"
echo "Scanning: $SCAN_DIR"
echo "========================================="

OUTPUT="webshell_scan_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== WEB SHELL SCAN REPORT ==="
echo "Scan date: $(date)"
echo "Directory: $SCAN_DIR"
echo ""

# Common web shell patterns
PATTERNS=(
    "eval.*base64_decode"
    "system.*\\\$_"
    "exec.*\\\$_"
    "shell_exec.*\\\$_"
    "passthru.*\\\$_"
    "proc_open"
    "popen.*\\\$_"
    "curl_exec"
    "curl_multi_exec"
    "parse_ini_file.*\\\$_"
    "show_source"
    "file_get_contents.*\\\$_"
    "file_put_contents.*\\\$_"
    "fputs.*\\\$_"
    "fwrite.*\\\$_"
    "assert.*\\\$_"
    "create_function"
    "base64_decode.*eval"
    "gzinflate.*base64"
    "eval.*gzuncompress"
    "preg_replace.*\\/e"
    "\\$\\{.*\\(.*\\).*\\}"
)

echo "=== SCANNING FOR SUSPICIOUS PHP FILES ==="
for pattern in "${PATTERNS[@]}"; do
    echo -e "\nPattern: $pattern"
    find "$SCAN_DIR" -type f -name "*.php" -exec grep -l "$pattern" {} \; 2>/dev/null
done

echo -e "\n=== CHECKING FOR SUSPICIOUS FILE NAMES ==="
find "$SCAN_DIR" -type f \( -name "*shell*.php" -o -name "*cmd*.php" -o -name "*backdoor*.php" -o -name "c99*.php" -o -name "r57*.php" -o -name "b374k*.php" \) 2>/dev/null

echo -e "\n=== RECENTLY MODIFIED PHP FILES (last 24 hours) ==="
find "$SCAN_DIR" -type f -name "*.php" -mtime -1 -ls 2>/dev/null

echo -e "\n=== CHECKING UPLOAD DIRECTORIES ==="
find "$SCAN_DIR" -type d -name "*upload*" -o -name "*temp*" -o -name "*tmp*" 2>/dev/null | while read dir; do
    echo -e "\nDirectory: $dir"
    find "$dir" -type f -name "*.php" -ls 2>/dev/null
done

echo -e "\n=== WORLD-WRITABLE PHP FILES ==="
find "$SCAN_DIR" -type f -name "*.php" -perm -0002 -ls 2>/dev/null

echo -e "\n=== PHP FILES OWNED BY UNEXPECTED USERS ==="
find "$SCAN_DIR" -type f -name "*.php" ! -user www-data ! -user nginx ! -user apache ! -user root -ls 2>/dev/null

} | tee "$OUTPUT"

echo ""
echo "========================================="
echo "SCAN COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="

################################################################################
# File: utilities/18_network_monitor.sh
# Purpose: Monitor network connections in real-time
# Usage: sudo ./18_network_monitor.sh
################################################################################
#!/bin/bash

echo "========================================="
echo "NETWORK CONNECTION MONITOR"
echo "Press Ctrl+C to stop"
echo "========================================="

LOGFILE="/root/network_monitor_$(date +%Y%m%d_%H%M%S).log"

while true; do
    clear
    echo "=== NETWORK MONITOR - $(date) ==="
    echo ""
    
    echo "=== ESTABLISHED CONNECTIONS ==="
    ss -tupn 2>/dev/null | grep ESTAB || netstat -tupn 2>/dev/null | grep ESTABLISHED
    
    echo -e "\n=== LISTENING PORTS ==="
    ss -tulpn 2>/dev/null | grep LISTEN || netstat -tulpn 2>/dev/null | grep LISTEN
    
    echo -e "\n=== TOP 10 CONNECTIONS BY IP ==="
    ss -tupn 2>/dev/null | grep ESTAB | awk '{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10 || \
    netstat -tupn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
    
    # Log connections
    echo "=== $(date) ===" >> "$LOGFILE"
    ss -tupn 2>/dev/null >> "$LOGFILE" || netstat -tupn 2>/dev/null >> "$LOGFILE"
    echo "" >> "$LOGFILE"
    
    sleep 5
done

################################################################################
# File: utilities/19_password_strength.sh
# Purpose: Check password strength for all users
# Usage: sudo ./19_password_strength.sh
################################################################################
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "PASSWORD STRENGTH CHECK - $(date)"
echo "========================================="

# Check if john the ripper is available
if ! command -v john &>/dev/null; then
    echo "[!] John the Ripper not installed"
    echo "Install with: sudo apt install john"
    echo ""
    echo "Performing basic checks instead..."
    echo ""
fi

# Get users with passwords
USERS=$(awk -F: '$2 !~ /^!|^\*/ && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null)

echo "=== USERS WITH PASSWORDS ==="
echo "$USERS"
echo ""

# Check for empty passwords
echo "=== CHECKING FOR EMPTY PASSWORDS ==="
awk -F: '($2 == "" || $2 == "!") && $3 >= 1000 {print $1 " has no password!"}' /etc/shadow 2>/dev/null
echo ""

# Check password aging
echo "=== PASSWORD AGING INFORMATION ==="
for user in $USERS; do
    chage -l "$user" 2>/dev/null | grep "Password expires"
done
echo ""

# Check for accounts with no expiry
echo "=== ACCOUNTS WITH NO PASSWORD EXPIRY ==="
awk -F: '$5 == 99999 && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null
echo ""

echo "========================================="
echo "TIP: Ensure all passwords are at least 12 characters"
echo "with uppercase, lowercase, numbers, and symbols"
echo "========================================="

################################################################################
# File: utilities/20_generate_report.sh
# Purpose: Generate final incident report template
# Usage: ./20_generate_report.sh
################################################################################
#!/bin/bash

OUTPUT="FINAL_INCIDENT_REPORT_$(date +%Y%m%d_%H%M%S).md"

cat > "$OUTPUT" << 'EOF'
# INCIDENT RESPONSE REPORT
## IRSeC Competition

**Date:** [Competition Date]  
**Team:** [Your Team Name]  
**Team Members:** [List all members]  
**Report Prepared By:** [Your Name]

---

## EXECUTIVE SUMMARY

[Provide a brief 2-3 paragraph overview of the competition, major incidents encountered, and overall team performance]

---

## SYSTEM INVENTORY

### Systems Under Our Control

| System | IP Address | OS | Role | Services |
|--------|------------|----|----- |----------|
| System 1 | 10.0.0.1 | Ubuntu 20.04 | Web Server | Apache, MySQL |
| System 2 | 10.0.0.2 | Windows Server 2019 | Domain Controller | AD, DNS |
| System 3 | 10.0.0.3 | CentOS 8 | Mail Server | Postfix, Dovecot |
| System 4 | 10.0.0.4 | Windows 10 | Workstation | IIS, SQL Server |

---

## TIMELINE OF EVENTS

### Initial Phase (00:00 - 00:05)

**00:00:30 - System Enumeration**
- Action: Deployed enumeration scripts on all systems
- Findings: Discovered [X] systems, [Y] services running
- Team Member: [Name]

**00:01:00 - Password Rotation**
- Action: Changed all default passwords
- Systems: All 4 systems
- New password documented in secure location
- Team Member: [Name]

**00:02:00 - Firewall Configuration**
- Action: Enabled firewalls on all systems
- Configuration: Default deny inbound, allow essential services
- Team Member: [Name]

**00:03:30 - SSH/RDP Hardening**
- Action: Hardened remote access
- Changes: Disabled root login, limited auth tries, configured timeouts
- Team Member: [Name]

**00:05:00 - Initial Threat Hunt**
- Action: Ran threat hunting scripts
- Findings: [Describe any backdoors found]
- Team Member: [Name]

### Incident 1: [Title] (00:15 - 00:25)

**Discovery:**
- Time: 00:15:23
- How Detected: [Monitoring alert / Log analysis / Manual inspection]
- Initial Indicator: [What tipped you off]

**Investigation:**
- Attack Vector: [How did the attacker get in]
- Affected Systems: [List systems]
- Compromised Accounts: [Any compromised accounts]
- IOCs Identified:
  - IP Addresses: [List suspicious IPs]
  - File Hashes: [If applicable]
  - Suspicious Files: [Paths to malicious files]
  - Processes: [Suspicious process names/PIDs]

**Impact:**
- Confidentiality: [Was data accessed?]
- Integrity: [Were files modified?]
- Availability: [Were services disrupted?]

**Response Actions:**
1. [00:16:00] Isolated affected system from network
2. [00:17:30] Killed malicious process (PID: XXXX)
3. [00:18:00] Removed backdoor user account
4. [00:19:00] Deleted web shell at /var/www/html/shell.php
5. [00:20:00] Changed passwords for all accounts
6. [00:21:00] Restored service
7. [00:22:00] Verified system integrity
8. [00:23:00] Resumed monitoring

**Evidence Collected:**
- Screenshots: [Describe]
- Log excerpts: [Describe]
- Files preserved: [List]

**Lessons Learned:**
- Root Cause: [What vulnerability was exploited]
- Prevention: [How to prevent in future]

### Incident 2: [Title] (00:45 - 01:00)

[Repeat same structure as Incident 1]

### Incident 3: [Title] (01:30 - 01:45)

[Repeat same structure]

---

## INJECT RESPONSES

### Inject 1: [Title]

**Received:** 00:30:00  
**Completed:** 00:42:00  
**Point Value:** 50 points  

**Requirements:**
- [List inject requirements]

**Actions Taken:**
- [Step-by-step what you did]

**Verification:**
- [How you verified completion]
- [Screenshots/evidence]

**Challenges:**
- [Any difficulties encountered]

### Inject 2: [Title]

[Repeat for each inject]

---

## SECURITY MEASURES IMPLEMENTED

### Network Security

**Firewall Configuration:**
- Default deny inbound traffic
- Allow only: SSH (22), HTTP (80), HTTPS (443), DNS (53)
- Egress filtering: Blocked suspicious IPs
- Rate limiting implemented

**Network Monitoring:**
- Continuous monitoring script deployed
- IDS/IPS: [If applicable]
- Traffic analysis performed every 30 minutes

### System Hardening

**Linux Systems:**
- Password policies: 12 character minimum, complexity required
- SSH: Root login disabled, key-based auth encouraged, max 3 auth tries
- Services: Disabled telnet, FTP, unnecessary services
- File permissions: Secured sensitive files (600/644/755)
- Audit logging: Enabled auditd
- Regular updates applied

**Windows Systems:**
- Group Policy: Security baseline applied
- User accounts: Disabled guest, removed unauthorized users
- Services: Disabled unnecessary services
- Windows Firewall: Enabled with restrictive rules
- Audit policies: Enabled for all categories
- Windows Defender: Updated and running

### Application Security

**Web Servers:**
- Removed default pages
- Disabled directory listing
- Hidden server version
- ModSecurity/WAF enabled
- SSL/TLS configured
- Regular web shell scans

**Databases:**
- Changed default passwords
- Removed test databases
- Disabled remote root access
- Query logging enabled
- Least privilege principle applied

**Other Services:**
- DNS: Restricted zone transfers
- Mail: Prevented open relay, SPF/DKIM configured
- FTP: Disabled anonymous access, chroot enabled

---

## INDICATORS OF COMPROMISE (IOCs)

### Network IOCs

| IP Address | Port | First Seen | Activity | Action Taken |
|------------|------|------------|----------|--------------|
| 192.168.1.100 | 4444 | 00:15 | Reverse shell | Blocked at firewall |
| 10.10.10.50 | 80 | 00:45 | SQL injection | Blocked at firewall |

### File IOCs

| File Path | Hash (if available) | Description | Action Taken |
|-----------|---------------------|-------------|--------------|
| /var/www/html/shell.php | - | Web shell | Deleted |
| /tmp/.hidden | - | Backdoor script | Deleted |

### Account IOCs

| Username | System | Description | Action Taken |
|----------|--------|-------------|--------------|
| backdoor | Linux-01 | Unauthorized user | Deleted |
| hacker | Windows-DC | Unauthorized admin | Deleted |

---

## ATTACK PATTERNS OBSERVED

### Attack Pattern 1: SQL Injection
- **Frequency:** [Number of attempts]
- **Target:** Web application login form
- **Success Rate:** 0% (blocked by input validation)
- **Mitigation:** Implemented prepared statements

### Attack Pattern 2: Brute Force SSH
- **Frequency:** [Number of attempts]
- **Target:** All Linux systems
- **Success Rate:** 0% (fail2ban blocked after 3 attempts)
- **Mitigation:** Fail2ban with 3 try limit

[Continue for other patterns]

---

## CHALLENGES ENCOUNTERED

1. **Challenge:** [Describe challenge]
   - **Impact:** [How it affected response]
   - **Resolution:** [How you overcame it]

2. **Challenge:** [Describe challenge]
   - **Impact:** [How it affected response]
   - **Resolution:** [How you overcame it]

---

## RECOMMENDATIONS

### Immediate Actions (If This Were Real)

1. **Password Management**
   - Implement password manager
   - Enforce MFA on all administrative accounts
   - Regular password rotation policy

2. **Network Segmentation**
   - Separate production and admin networks
   - Implement VLANs
   - DMZ for public-facing services

3. **Monitoring and Alerting**
   - Deploy SIEM solution
   - Real-time alerting for critical events
   - Automated incident response playbooks

### Long-Term Improvements

1. **Security Training**
   - Regular security awareness training
   - Phishing simulations
   - Incident response drills

2. **Infrastructure**
   - Upgrade legacy systems
   - Implement security orchestration
   - Regular penetration testing

3. **Documentation**
   - Maintain updated network diagrams
   - Document all security controls
   - Create incident response playbooks

---

## STATISTICS

**Overall Performance:**
- Total Incidents Detected: [X]
- Total Incidents Resolved: [X]
- Average Response Time: [X minutes]
- Injects Completed: [X / Y]
- Points Earned: [Total]

**System Uptime:**
- System 1: [%]
- System 2: [%]
- System 3: [%]
- System 4: [%]

**Attack Statistics:**
- Total Attack Attempts Detected: [X]
- Successful Attacks: [X]
- Blocked Attacks: [X]
- Attack Success Rate: [X%]

---

## CONCLUSION

[2-3 paragraphs summarizing:
- Overall team performance
- Key successes
- Areas for improvement
- Lessons learned
- Final thoughts]

---

## APPENDICES

### Appendix A: Configuration Files
[Include sanitized copies of key configurations]

### Appendix B: Log Excerpts
[Include relevant log entries]

### Appendix C: Screenshots
[Reference evidence screenshots]

### Appendix D: Tools Used
- Enumeration: Custom bash scripts
- Monitoring: Custom monitoring scripts
- Log Analysis: grep, awk, sed
- Network Analysis: ss, netstat, tcpdump
- Web Security: ModSecurity
- Password Security: Automated rotation scripts

---

**Report End**

*This report contains sensitive security information and should be handled accordingly.*
EOF

echo "========================================="
echo "REPORT TEMPLATE GENERATED"
echo "File: $OUTPUT"
echo "========================================="
echo ""
echo "Edit this template and fill in all sections"
echo "during and after the competition."
echo ""
