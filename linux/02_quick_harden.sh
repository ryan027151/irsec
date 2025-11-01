#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "QUICK HARDENING - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - Quick hardening script started" >> /root/activity_log.txt
echo "========================================="

# Collect teammate IPs
echo ""
echo "[*] Enter IP addresses for your 3 teammates (one at a time)"
echo "[*] Press Enter after each IP. Leave blank and press Enter when done."
echo ""

TEAMMATE_IPS=()
for i in 1 2 3; do
    read -p "Teammate $i IP address: " ip
    if [ -n "$ip" ]; then
        # Basic IP validation
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            TEAMMATE_IPS+=("$ip")
            echo "[+] Added: $ip"
        else
            echo "[!] Invalid IP format, skipping..."
        fi
    fi
done

# Get current machine's IP
MY_IP=$(hostname -I | awk '{print $1}')
echo "[+] Your IP: $MY_IP"

echo ""
echo "[+] Teammate IPs to whitelist:"
for ip in "${TEAMMATE_IPS[@]}"; do
    echo "    - $ip"
done
echo ""

read -p "Proceed with hardening? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Create backup directory
BACKUP_DIR="/root/backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "[+] Backup directory: $BACKUP_DIR"

# Backup critical files
echo "[+] Backing up critical configuration files..."
cp /etc/passwd "$BACKUP_DIR/"
cp /etc/shadow "$BACKUP_DIR/"
cp /etc/group "$BACKUP_DIR/"
cp /etc/sudoers "$BACKUP_DIR/"
cp /etc/ssh/sshd_config "$BACKUP_DIR/"
cp /etc/crontab "$BACKUP_DIR/"
[ -d /etc/apache2 ] && cp -r /etc/apache2 "$BACKUP_DIR/"
[ -d /etc/nginx ] && cp -r /etc/nginx "$BACKUP_DIR/"

# Enable and configure firewall
echo "[+] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force enable
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - UFW firewall enabled" >> /root/activity_log.txt
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH from teammate IPs
    for ip in "${TEAMMATE_IPS[@]}"; do
        ufw allow from "$ip" to any port 22 proto tcp comment "Teammate SSH"
        echo "[+] UFW: Allowed SSH from $ip"
    done
    
    # Allow HTTP/HTTPS from all (or restrict if needed)
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow SSH from localhost
    ufw allow from 127.0.0.1 to any port 22
    
    ufw reload
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - UFW firewall reloaded with new rules" >> /root/activity_log.txt
    echo "UFW firewall enabled"
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Firewalld enabled and started" >> /root/activity_log.txt
    firewall-cmd --set-default-zone=public
    
    # Create rich rules for teammate SSH access
    for ip in "${TEAMMATE_IPS[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' port port='22' protocol='tcp' accept"
        echo "[+] Firewalld: Allowed SSH from $ip"
    done
    
    # Allow HTTP/HTTPS from all
    firewall-cmd --zone=public --add-service=http --permanent
    firewall-cmd --zone=public --add-service=https --permanent
    
    firewall-cmd --reload
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Firewalld reloaded with new rules" >> /root/activity_log.txt
    echo "Firewalld enabled"
else
    # Fallback to iptables
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH from teammate IPs
    for ip in "${TEAMMATE_IPS[@]}"; do
        iptables -A INPUT -p tcp -s "$ip" --dport 22 -j ACCEPT
        echo "[+] iptables: Allowed SSH from $ip"
    done
    
    # Allow HTTP/HTTPS from all
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Applied basic iptables rules" >> /root/activity_log.txt
    echo "Basic iptables rules applied"
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > "$BACKUP_DIR/iptables_rules"
    fi
fi

# Save teammate IPs for reference
echo "[+] Saving teammate IPs..."
cat > /root/team_ips.txt << EOF
# Team IP Whitelist - Created $(date)
# Your IP: $MY_IP
EOF

for ip in "${TEAMMATE_IPS[@]}"; do
    echo "$ip" >> /root/team_ips.txt
done
echo "Team IPs saved to /root/team_ips.txt"

# Harden SSH
echo "[+] Hardening SSH configuration..."
sed -i.bak 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Hardened SSH configuration in /etc/ssh/sshd_config" >> /root/activity_log.txt

# Restart SSH
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
echo "$(TZ='America/New_York' date) $(basename \"$0\") - SSH service restarted" >> /root/activity_log.txt
echo "SSH hardened and restarted"

# Enable audit logging
echo "[+] Enabling audit logging..."
if command -v auditd &> /dev/null; then
    systemctl enable auditd
    systemctl start auditd
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Auditd service enabled and started" >> /root/activity_log.txt
    echo "Auditd enabled"
fi

# Disable unnecessary services
echo "[+] Disabling risky services..."
RISKY_SERVICES=("telnet" "rsh" "rlogin" "vsftpd" "pure-ftpd" "proftpd")
for service in "${RISKY_SERVICES[@]}"; do
    systemctl disable "$service" 2>/dev/null
    systemctl stop "$service" 2>/dev/null
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Disabled and stopped risky service: $service" >> /root/activity_log.txt
done

# Set password policies
echo "[+] Configuring password policies..."
sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set password policies in /etc/login.defs" >> /root/activity_log.txt

# Enable password quality requirements
if [ -f /etc/security/pwquality.conf ]; then
    sed -i.bak 's/^# minlen.*/minlen = 12/' /etc/security/pwquality.conf
    sed -i 's/^# dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
    echo "Password quality requirements set"
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set password quality requirements in /etc/security/pwquality.conf" >> /root/activity_log.txt
fi

# Enable SYN cookie protection
echo "[+] Enabling SYN flood protection..."
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=5
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Enabled SYN flood protection" >> /root/activity_log.txt

# Disable IP forwarding
echo "[+] Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Disabled IP forwarding" >> /root/activity_log.txt

# Enable exec-shield
sysctl -w kernel.exec-shield=1 2>/dev/null
sysctl -w kernel.randomize_va_space=2 2>/dev/null
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Enabled ASLR (randomize_va_space)" >> /root/activity_log.txt

# Set secure file permissions
echo "[+] Setting secure permissions on sensitive files..."
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow 2>/dev/null
chmod 600 /etc/ssh/sshd_config
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set secure permissions on sensitive files" >> /root/activity_log.txt

# Check for common backdoor accounts
echo "[+] Checking for suspicious accounts..."
SUSPICIOUS=("backdoor" "hacker" "test" "guest" "admin")
for user in "${SUSPICIOUS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "[!] FOUND SUSPICIOUS USER: $user"
    fi
done

echo "========================================="
echo "$(TZ='America/New_York' date) $(basename "$0") - Quick hardening script finished" >> /root/activity_log.txt
echo "QUICK HARDENING COMPLETE"
echo "Backups stored in: $BACKUP_DIR"
echo "Team IPs whitelisted: ${#TEAMMATE_IPS[@]}"
echo "Team IPs saved to: /root/team_ips.txt"
echo "========================================="
