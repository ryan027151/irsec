#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

OUTPUT="/root/threat_hunt_$(date +%Y%m%d_%H%M%S).txt"
WAZUH_LOG="/var/ossec/logs/active-responses.log"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "========================================="
echo "THREAT HUNTING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - Threat hunting script started" >> /root/activity_log.txt
echo "========================================="

# Log to Wazuh if available
if [ -f "$WAZUH_LOG" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Manual threat hunt initiated" >> "$WAZUH_LOG"
fi

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

# Calculate summary statistics
WEB_SHELLS=$(grep -c "eval\|base64_decode" "$OUTPUT" 2>/dev/null || echo "0")
SUSPICIOUS_PROCS=$(ps aux | grep -E 'nc|ncat|netcat|/bin/sh -i|/bin/bash -i' | grep -v grep | wc -l)
UNUSUAL_CONNECTIONS=$(ss -tupn | grep ESTAB | grep -v ":22\|:80\|:443\|:53" | wc -l)
SUID_FILES=$(find / -perm -4000 -type f 2>/dev/null | grep -v "/bin/\|/usr/bin/\|/sbin/\|/usr/sbin/" | wc -l)

echo ""
echo "=== SUMMARY ==="
echo "Potential web shell indicators: $WEB_SHELLS"
echo "Suspicious processes: $SUSPICIOUS_PROCS"
echo "Unusual network connections: $UNUSUAL_CONNECTIONS"
echo "Unusual SUID binaries: $SUID_FILES"
echo ""

# Log summary to Wazuh if available
if [ -f "$WAZUH_LOG" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Threat hunt complete - Web shells: $WEB_SHELLS, Suspicious procs: $SUSPICIOUS_PROCS, Unusual connections: $UNUSUAL_CONNECTIONS" >> "$WAZUH_LOG"
fi

# Alert if critical findings
if [ "$SUSPICIOUS_PROCS" -gt 0 ] || [ "$WEB_SHELLS" -gt 5 ]; then
    echo -e "${RED}[!] CRITICAL FINDINGS DETECTED - Review $OUTPUT immediately!${NC}"
    if [ -f "$WAZUH_LOG" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): CRITICAL - Threat hunt found suspicious activity!" >> "$WAZUH_LOG"
    fi
fi

# Check for unknown users interactively
echo ""
echo "========================================="
echo "CHECKING FOR UNKNOWN USERS"
echo "========================================="

# Define known legitimate users (customize this list for your environment)
KNOWN_USERS=("root" "whiteteam" "kim" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "messagebus" "systemd-timesync" "syslog" "_apt" "tss" "uuidd" "tcpdump" "landscape" "fwupd-refresh" "pollinate" "sshd" "mysql" "wazuh" "ossec")

# Get all human users (UID >= 1000)
ALL_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

UNKNOWN_FOUND=0

for user in $ALL_USERS; do
    # Check if user is in known users list
    if [[ ! " ${KNOWN_USERS[@]} " =~ " ${user} " ]]; then
        UNKNOWN_FOUND=1
        echo -e "${YELLOW}[!] Found unknown user: ${RED}$user${NC}"
        
        # Show user details
        echo "    Details:"
        grep "^$user:" /etc/passwd
        echo "    Last login:"
        lastlog -u "$user" 2>/dev/null | tail -1
        echo "    User groups:"
        groups "$user" 2>/dev/null
        echo "    Account status:"
        passwd -S "$user" 2>/dev/null
        echo ""
        
        # Ask for action
        read -p "Do you want to BLOCK this user? (y/n): " response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            # Lock the account (disable login)
            passwd -l "$user" 2>/dev/null
            usermod -L "$user" 2>/dev/null
            
            # Kill all processes owned by the user
            pkill -KILL -u "$user" 2>/dev/null
            
            # Remove SSH authorized keys
            if [ -d "/home/$user/.ssh" ]; then
                rm -f "/home/$user/.ssh/authorized_keys" 2>/dev/null
                echo "    Removed SSH authorized keys"
            fi
            
            echo -e "    ${GREEN}[+] User $user has been BLOCKED (account locked, processes killed)${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S'): User $user blocked by administrator" >> /root/activity_log.txt
            echo "User $user: BLOCKED" >> /root/blocked_users.log
            
            # Log to Wazuh
            if [ -f "$WAZUH_LOG" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S'): Suspicious user $user blocked by administrator" >> "$WAZUH_LOG"
            fi
        else
            echo -e "    ${YELLOW}[*] User $user was NOT blocked (marked as legitimate)${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S'): User $user reviewed and marked as legitimate" >> /root/activity_log.txt
            
            # Optionally add to known users list for future runs
            read -p "    Add $user to known users list? (y/n): " add_response
            if [[ "$add_response" =~ ^[Yy]$ ]]; then
                echo "$user" >> /root/known_users.txt
                echo "    Added to /root/known_users.txt"
            fi
        fi
        echo ""
    fi
done

if [ $UNKNOWN_FOUND -eq 0 ]; then
    echo -e "${GREEN}[+] No unknown users found. All user accounts are recognized.${NC}"
fi

echo "========================================="
echo "USER AUDIT COMPLETE"
echo "========================================="

# Final summary
echo ""
echo "=== FINAL SUMMARY ==="
echo "Threat hunt report: $OUTPUT"
echo "Blocked users log: /root/blocked_users.log"
echo "Activity log: /root/activity_log.txt"
echo ""
echo "To review blocked users: cat /root/blocked_users.log"
echo "To unblock a user: passwd -u USERNAME && usermod -U USERNAME"
echo ""
