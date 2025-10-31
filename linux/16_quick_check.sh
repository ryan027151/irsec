
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
