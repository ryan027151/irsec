
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

# Add security settings
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
