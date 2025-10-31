
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v apache2 &>/dev/null && ! command -v httpd &>/dev/null; then
    echo "Apache not found"
    exit 1
fi

echo "========================================="
echo "APACHE HARDENING - $(date)"
echo "$(date) $(basename "$0") - Apache hardening script started" >> /root/activity_log.txt
echo "========================================="

# Determine Apache binary and config
if command -v apache2 &>/dev/null; then
    APACHE_BIN="apache2"
    APACHE_CONF="/etc/apache2/apache2.conf"
    APACHE_DIR="/etc/apache2"
    SITES_DIR="/etc/apache2/sites-available"
else
    APACHE_BIN="httpd"
    APACHE_CONF="/etc/httpd/conf/httpd.conf"
    APACHE_DIR="/etc/httpd"
    SITES_DIR="/etc/httpd/conf.d"
fi

# Backup configuration
BACKUP_DIR="/root/apache_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r "$APACHE_DIR" "$BACKUP_DIR/"
echo "[+] Backup created: $BACKUP_DIR"

# Remove default pages
echo "[+] Removing default pages..."
rm -f /var/www/html/index.html 2>/dev/null
rm -f /var/www/html/index.nginx-debian.html 2>/dev/null
echo "Apache2 Secured" > /var/www/html/index.html
echo "$(date) $(basename \"$0\") - Removed default Apache page and created placeholder" >> /root/activity_log.txt

# Create security.conf
SECURITY_CONF="$APACHE_DIR/conf-available/security-custom.conf"
if [ -d "$APACHE_DIR/conf-available" ]; then
    echo "[+] Creating security configuration..."
    cat > "$SECURITY_CONF" << 'EOF'
# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable directory listing
<Directory /var/www/>
    Options -Indexes
    AllowOverride None
    Require all granted


# Disable unnecessary HTTP methods

    
        Require all denied
    


# Clickjacking protection
Header always append X-Frame-Options SAMEORIGIN

# XSS Protection
Header set X-XSS-Protection "1; mode=block"

# Prevent MIME sniffing
Header set X-Content-Type-Options nosniff

# Disable ETags
FileETag None

# Timeout settings
Timeout 60
KeepAliveTimeout 5

# Limit request size (10MB)
LimitRequestBody 10485760
EOF

    # Enable the configuration
    if command -v a2enconf &>/dev/null; then
        a2enconf security-custom
        echo "$(date) $(basename \"$0\") - Created and enabled custom Apache security configuration" >> /root/activity_log.txt
    fi
fi

# Set proper permissions
echo "[+] Setting secure file permissions..."
find /var/www -type d -exec chmod 755 {} \;
find /var/www -type f -exec chmod 644 {} \;
chown -R www-data:www-data /var/www 2>/dev/null || chown -R apache:apache /var/www 2>/dev/null
echo "$(date) $(basename \"$0\") - Set secure permissions on /var/www" >> /root/activity_log.txt

# Disable unnecessary modules
echo "[+] Disabling unnecessary modules..."
DISABLE_MODS="autoindex status userdir"
for mod in $DISABLE_MODS; do
    a2dismod $mod 2>/dev/null
    echo "$(date) $(basename \"$0\") - Disabled unnecessary Apache module: $mod" >> /root/activity_log.txt
done

# Enable security modules
echo "[+] Enabling security modules..."
ENABLE_MODS="headers rewrite ssl"
for mod in $ENABLE_MODS; do
    a2enmod $mod 2>/dev/null
    echo "$(date) $(basename \"$0\") - Enabled security Apache module: $mod" >> /root/activity_log.txt
done

# Test configuration
echo "[+] Testing Apache configuration..."
$APACHE_BIN -t

# Restart Apache
read -p "Restart Apache now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null
    echo "$(date) $(basename \"$0\") - Restarted Apache service" >> /root/activity_log.txt
    echo "[+] Apache restarted"
fi

echo "========================================="
echo "$(date) $(basename "$0") - Apache hardening script finished" >> /root/activity_log.txt
echo "APACHE HARDENING COMPLETE"
echo "========================================="
