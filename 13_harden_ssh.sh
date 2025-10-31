
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "SSH HARDENING - $(date)"
echo "$(date) $(basename "$0") - SSH hardening script started" >> /root/activity_log.txt
echo "========================================="

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original config
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
echo "[+] Backup created"

# Apply hardening
echo "[+] Applying SSH hardening..."

# Function to set or replace config value
set_config() {
    local key="$1"
    local value="$2"
    if grep -q "^#*${key}" "$SSHD_CONFIG"; then
        sed -i "s/^#*${key}.*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# Apply all hardening settings
set_config "PermitRootLogin" "no"
set_config "PasswordAuthentication" "yes"
set_config "PermitEmptyPasswords" "no"
set_config "X11Forwarding" "no"
set_config "MaxAuthTries" "3"
set_config "ClientAliveInterval" "300"
set_config "ClientAliveCountMax" "2"
set_config "Protocol" "2"
set_config "LogLevel" "VERBOSE"
set_config "MaxSessions" "2"
set_config "TCPKeepAlive" "no"
set_config "AllowTcpForwarding" "no"
set_config "AllowAgentForwarding" "no"
set_config "PermitUserEnvironment" "no"
echo "$(date) $(basename \"$0\") - Applied hardening settings to $SSHD_CONFIG" >> /root/activity_log.txt

# Strong ciphers and MACs
if ! grep -q "^Ciphers" "$SSHD_CONFIG"; then
    cat >> "$SSHD_CONFIG" << 'EOF'

# Strong ciphers only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF
    echo "$(date) $(basename \"$0\") - Added strong ciphers, MACs, and KexAlgorithms to $SSHD_CONFIG" >> /root/activity_log.txt
fi

# Test configuration
echo "[+] Testing SSH configuration..."
sshd -t
if [ $? -ne 0 ]; then
    echo "[!] SSH configuration test failed! Restoring backup..."
    cp "${SSHD_CONFIG}.backup."* "$SSHD_CONFIG"
    exit 1
fi

# Restart SSH
read -p "Restart SSH now? (y/N): " restart
if [ "$restart" == "y" ]; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo "$(date) $(basename \"$0\") - Restarted SSH service" >> /root/activity_log.txt
    echo "[+] SSH restarted"
fi

echo "========================================="
echo "$(date) $(basename "$0") - SSH hardening script finished" >> /root/activity_log.txt
echo "SSH HARDENING COMPLETE"
echo "========================================="
