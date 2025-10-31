
#!/bin/bash

echo "========================================="
echo "USER AUDIT - $(date)"
echo "$(date) $(basename "$0") - User audit script started" >> /root/activity_log.txt
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

