```bash
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
```
