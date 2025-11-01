#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if ! command -v named &>/dev/null; then
    echo "BIND DNS server (named) not found"
    exit 1
fi

echo "========================================="
echo "DNS (BIND) HARDENING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - DNS (BIND) hardening script started" >> /root/activity_log.txt
echo "========================================="

NAMED_CONF="/etc/named.conf"

if [ ! -f "$NAMED_CONF" ]; then
    echo "[!] BIND configuration file not found at $NAMED_CONF"
    exit 1
fi

# Backup config
cp "$NAMED_CONF" "${NAMED_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
echo "[+] Backup created: ${NAMED_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

# Add hardening options to the options block
# This is a simple approach; a more robust solution would be to parse and modify the options block.
echo "[+] Adding hardening options to $NAMED_CONF..."

# Check if options block exists
if grep -q "options {" "$NAMED_CONF"; then
    # Add settings inside the existing options block
    sed -i '/options {/a \
    allow-transfer { none; }; \
    recursion no; \
    version "Not Available"; \
    querylog yes; \
    notify no;' "$NAMED_CONF"
else
    # Add a new options block
    cat >> "$NAMED_CONF" << 'EOF'

// Custom Security Hardening
options {
    allow-transfer { none; };
    recursion no;
    version "Not Available";
    querylog yes;
    notify no;
};
EOF
fi

echo "[+] DNS hardening configuration added"
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Added hardening options to BIND configuration" >> /root/activity_log.txt

# Test configuration
echo "[+] Testing BIND configuration..."
named-checkconf
if [ $? -ne 0 ]; then
    echo "[!] Configuration test failed. Restoring backup."
    cp "${NAMED_CONF}.backup."* "$NAMED_CONF"
    exit 1
fi

# Restart DNS
read -p "Restart BIND (named) now? (y/N): " restart
if [[ "$restart" =~ ^[Yy]$ ]]; then
    systemctl restart named
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Restarted BIND DNS service (named)" >> /root/activity_log.txt
    echo "[+] BIND (named) restarted"
fi

echo "========================================="
echo "$(TZ='America/New_York' date) $(basename "$0") - DNS (BIND) hardening script finished" >> /root/activity_log.txt
echo "DNS HARDENING COMPLETE"
echo "========================================="
