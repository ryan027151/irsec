
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "PASSWORD STRENGTH CHECK - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - Password strength check script started" >> /root/activity_log.txt
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
