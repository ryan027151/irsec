#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "MYSQL/MARIADB HARDENING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - MySQL/MariaDB hardening script started" >> /root/activity_log.txt
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
-- Change root password (modern syntax)
ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_PASS';
-- Change root password (legacy syntax - fallback)
-- UPDATE mysql.user SET Password=PASSWORD('$NEW_PASS') WHERE User='root';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Disallow remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '1227.0.0.1', '::1');

-- Drop test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';

-- Flush privileges to apply changes
FLUSH PRIVILEGES;

-- Show remaining users
SELECT User, Host FROM mysql.user;
EOF

echo "[+] MySQL security hardening applied"
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Applied MySQL security hardening SQL commands" >> /root/activity_log.txt

# Secure my.cnf
echo "[+] Hardening MySQL configuration file..."
MY_CNF="/etc/my.cnf"

if [ ! -f "$MY_CNF" ]; then
    echo "[!] Configuration file not found at $MY_CNF. Skipping configuration hardening."
else
    # Backup config
    cp "$MY_CNF" "${MY_CNF}.backup.$(date +%Y%m%d_%H%M%S)"

    # Add security settings to a new file in conf.d for better management
    CONF_D_FILE="/etc/my.cnf.d/99-security-custom.cnf"
    echo "[+] Creating custom security config at $CONF_D_FILE"
    cat > "$CONF_D_FILE" << 'EOF'
[mysqld]
# Bind to localhost only to prevent remote connections
bind-address = 127.0.0.1

# Disable LOAD DATA LOCAL INFILE to prevent reading local files
local-infile=0

# Enable basic logging
general_log = 1
general_log_file = /var/log/mariadb/mariadb.log
log_error = /var/log/mariadb/mariadb-error.log

# Disable symbolic links to prevent filesystem exploits
symbolic-links=0
EOF

    echo "[+] MySQL configuration hardened"
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Hardened MySQL configuration" >> /root/activity_log.txt

    # Set secure file permissions
    chmod 644 "$MY_CNF"
    chmod 644 "$CONF_D_FILE"
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set secure permissions on MySQL config files" >> /root/activity_log.txt
fi

# Restart MySQL/MariaDB
read -p "Restart MySQL/MariaDB now? (y/N): " restart
if [[ "$restart" =~ ^[Yy]$ ]]; then
    systemctl restart mariadb 2>/dev/null || systemctl restart mysqld 2>/dev/null || systemctl restart mysql 2>/dev/null
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Restarted MySQL/MariaDB service" >> /root/activity_log.txt
    echo "[+] MySQL/MariaDB restarted"
fi

echo "========================================="
echo "$(TZ='America/New_York' date) $(basename "$0") - MySQL/MariaDB hardening script finished" >> /root/activity_log.txt
echo "MYSQL HARDENING COMPLETE"
echo "New root password has been set."
echo "========================================="
