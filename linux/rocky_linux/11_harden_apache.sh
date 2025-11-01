#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v httpd &>/dev/null; then
    echo "Apache (httpd) not found"
    exit 1
fi

echo "========================================="
echo "APACHE (HTTPD) HARDENING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - Apache hardening script started" >> /root/activity_log.txt
echo "========================================="

APACHE_BIN="httpd"
APACHE_DIR="/etc/httpd"
CONF_D_DIR="/etc/httpd/conf.d"

# Backup configuration
BACKUP_DIR="/root/httpd_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r "$APACHE_DIR" "$BACKUP_DIR/"
echo "[+] Backup created: $BACKUP_DIR"

# Disable default welcome page
echo "[+] Disabling default welcome page..."
if [ -f "$CONF_D_DIR/welcome.conf" ]; then
    mv "$CONF_D_DIR/welcome.conf" "$CONF_D_DIR/welcome.conf.disabled"
    echo "Disabled default welcome page config."
fi
echo "Security Hardened Page" > /var/www/html/index.html
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Disabled default Apache page and created placeholder" >> /root/activity_log.txt

# Create security.conf in conf.d
SECURITY_CONF="$CONF_D_DIR/99-security-custom.conf"
echo "[+] Creating security configuration at $SECURITY_CONF..."
cat > "$SECURITY_CONF" << 'EOF'
# Hide Apache version and other sensitive info
ServerTokens Prod
ServerSignature Off

# Disable directory listing globally
<Directory />
    Options -Indexes
    AllowOverride None
</Directory>

# Disable unnecessary HTTP methods (Trace)
TraceEnable Off

# Clickjacking protection
Header always set X-Frame-Options "SAMEORIGIN"

# XSS Protection
Header set X-XSS-Protection "1; mode=block"

# Prevent MIME sniffing
Header set X-Content-Type-Options "nosniff"

# Disable ETags to prevent tracking
FileETag None

# Timeout settings
Timeout 60
KeepAliveTimeout 5

# Limit request size (10MB)
LimitRequestBody 10485760
EOF
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Created custom Apache security configuration" >> /root/activity_log.txt

# Set proper permissions
echo "[+] Setting secure file permissions..."
chown -R apache:apache /var/www
find /var/www -type d -exec chmod 755 {} \;
find /var/www -type f -exec chmod 644 {} \;
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set secure permissions on /var/www" >> /root/activity_log.txt

# Test configuration
echo "[+] Testing Apache configuration..."
$APACHE_BIN -t
if [ $? -ne 0 ]; then
    echo "[!] Apache config test failed. Please review the changes before restarting."
    exit 1
fi

# Restart Apache
read -p "Restart Apache (httpd) now? (y/N): " restart
if [[ "$restart" =~ ^[Yy]$ ]]; then
    systemctl restart httpd
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Restarted httpd service" >> /root/activity_log.txt
    echo "[+] Apache (httpd) restarted"
fi

echo "========================================="
echo "$(TZ='America/New_YOrk' date) $(basename "$0") - Apache hardening script finished" >> /root/activity_log.txt
echo "APACHE HARDENING COMPLETE"
echo "========================================="
