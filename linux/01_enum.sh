#!/bin/bash

echo "==================================="
echo "SYSTEM ENUMERATION - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - System enumeration started" >> /root/activity_log.txt
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

