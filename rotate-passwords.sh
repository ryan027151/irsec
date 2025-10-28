```bash
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

# Log password changes
echo "$(date): Passwords rotated for all users" >> /root/password_changes.log

echo "========================================="
echo "PASSWORD ROTATION COMPLETE"
echo "New password: $NEW_PASSWORD"
echo "SAVE THIS SECURELY AND SHARE WITH TEAM"
echo "========================================="

echo ""
echo "**********************************"
echo "NEW PASSWORD: $NEW_PASSWORD"
echo "**********************************"
echo ""
```
