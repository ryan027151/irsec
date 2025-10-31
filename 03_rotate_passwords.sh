
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "PASSWORD ROTATION - $(date)"
echo "$(date) $(basename "$0") - Password rotation script started for all users" >> /root/activity_log.txt
echo "========================================="

# Get list of human users (UID >= 1000, has shell)
USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ && $1 != "nobody" {print $1}' /etc/passwd)

# Clear previous log file
> /root/password_changes.log
echo "Password Rotation Log - $(date)" >> /root/password_changes.log
echo "=========================================" >> /root/password_changes.log

echo "Rotating passwords for users..."
for user in $USERS; do
    NEW_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)
    echo "$user:$NEW_PASSWORD" | chpasswd
    if [ $? -eq 0 ]; then
        echo -e "[+] Password changed for $user: ${GREEN}$NEW_PASSWORD${NC}"
        echo "$user: $NEW_PASSWORD" >> /root/password_changes.log
        echo "$(date) $(basename \"$0\") - Rotated password for user: $user" >> /root/activity_log.txt
    else
        echo "[!] Failed to change password for: $user"
    fi
done

# Change root password
ROOT_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)
echo "root:$ROOT_PASSWORD" | chpasswd
if [ $? -eq 0 ]; then
    echo -e "[+] Root password changed: ${GREEN}$ROOT_PASSWORD${NC}"
    echo "root: $ROOT_PASSWORD" >> /root/password_changes.log
    echo "$(date) $(basename \"$0\") - Rotated password for user: root" >> /root/activity_log.txt
else
    echo "[!] Failed to change root password"
fi

echo "========================================="
echo "PASSWORD ROTATION COMPLETE"
echo "New passwords have been logged to /root/password_changes.log"
echo "========================================="

