
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v nginx &>/dev/null; then
    echo "Nginx not found"
    exit 1
fi

echo "========================================="
echo "NGINX HARDENING - $(date)"
echo "========================================="

NGINX_CONF="/etc/nginx/nginx.conf"
BACKUP_DIR="/root/nginx_backup_$(date +%Y%m%d_%H%M%S)"

# Backup configuration
mkdir -p "$BACKUP_DIR"
cp -r /etc/nginx "$BACKUP_DIR/"
echo "[+] Backup created: $BACKUP_DIR"

# Remove default pages
echo "[+] Removing default pages..."
rm -f /var/www/html/index.nginx-debian.html 2>/dev/null
echo "Nginx Secured" > /var/www/html/index.html

# Create security configuration
SECURITY_CONF="/etc/nginx/conf.d/security.conf"
echo "[+] Creating security configuration..."
cat > "$SECURITY_CONF" << 'EOF'
# Hide Nginx version
server_tokens off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_req_status 429;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 10;

# Buffer overflow protection
client_body_buffer_size 1K;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 2 1k;

# Timeouts
client_body_timeout 10;
client_header_timeout 10;
keepalive_timeout 5 5;
send_timeout 10;
EOF

# Set proper permissions
echo "[+] Setting secure file permissions..."
find /var/www -type d -exec chmod 755 {} \;
find /var/www -type f -exec chmod 644 {} \;
chown -R www-data:www-data /var/www 2>/dev/null

# Test configuration
echo "[+] Testing Nginx configuration..."
nginx -t

if [ $? -ne 0 ]; then
    echo "[!] Configuration test failed!"
    exit 1
fi

# Restart Nginx
read -p "Restart Nginx now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart nginx
    echo "[+] Nginx restarted"
fi

echo "========================================="
echo "NGINX HARDENING COMPLETE"
echo "========================================="
