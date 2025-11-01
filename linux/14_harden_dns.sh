
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v named &>/dev/null; then
    echo "BIND DNS server not found"
    exit 1
fi

echo "========================================="
echo "DNS (BIND) HARDENING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - DNS (BIND) hardening script started" >> /root/activity_log.txt
echo "========================================="

NAMED_CONF="/etc/bind/named.conf.options"
[ -f /etc/named.conf ] && NAMED_CONF="/etc/named.conf"

# Backup config
cp "$NAMED_CONF" "${NAMED_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
echo "[+] Backup created"

# Create hardened configuration
cat >> "$NAMED_CONF" << 'EOF'

// Security options
options {
    // Restrict zone transfers
    allow-transfer { none; };
    
    // Disable recursion for external queries
    recursion no;
    
    // Rate limiting
    rate-limit {
        responses-per-second 10;
        window 5;
    };
    
    // Hide version
    version "Not Available";
    
    // Enable query logging
    querylog yes;
    
    // Disable notify
    notify no;
};
EOF

echo "[+] DNS hardening configuration added"
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Added hardening options to BIND configuration file: $NAMED_CONF" >> /root/activity_log.txt

# Test configuration
named-checkconf
if [ $? -ne 0 ]; then
    echo "[!] Configuration test failed"
    exit 1
fi

# Restart DNS
read -p "Restart BIND now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Restarted BIND DNS service" >> /root/activity_log.txt
    echo "[+] BIND restarted"
fi

echo "========================================="
echo "$(TZ='America/New_York' date) $(basename "$0") - DNS (BIND) hardening script finished" >> /root/activity_log.txt
echo "DNS HARDENING COMPLETE"
echo "========================================="
