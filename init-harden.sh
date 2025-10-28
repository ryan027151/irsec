```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "QUICK HARDENING - $(date)"
echo "========================================="

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
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw reload
    echo "UFW firewall enabled"
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --set-default-zone=public
    firewall-cmd --zone=public --add-service=ssh --permanent
    firewall-cmd --zone=public --add-service=http --permanent
    firewall-cmd --zone=public --add-service=https --permanent
    firewall-cmd --reload
    echo "Firewalld enabled"
else
    # Fallback to iptables
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    echo "Basic iptables rules applied"
fi

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

# Restart SSH
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
echo "SSH hardened and restarted"

# Enable audit logging
echo "[+] Enabling audit logging..."
if command -v auditd &> /dev/null; then
    systemctl enable auditd
    systemctl start auditd
    echo "Auditd enabled"
fi

# Disable unnecessary services
echo "[+] Disabling risky services..."
RISKY_SERVICES=("telnet" "rsh" "rlogin" "vsftpd" "pure-ftpd" "proftpd")
for service in "${RISKY_SERVICES[@]}"; do
    systemctl disable "$service" 2>/dev/null
    systemctl stop "$service" 2>/dev/null
done

# Set password policies
echo "[+] Configuring password policies..."
sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Enable password quality requirements
if [ -f /etc/security/pwquality.conf ]; then
    sed -i.bak 's/^# minlen.*/minlen = 12/' /etc/security/pwquality.conf
    sed -i 's/^# dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
    echo "Password quality requirements set"
fi

# Enable SYN cookie protection
echo "[+] Enabling SYN flood protection..."
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=5

# Disable IP forwarding
echo "[+] Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0

# Enable exec-shield
sysctl -w kernel.exec-shield=1 2>/dev/null
sysctl -w kernel.randomize_va_space=2 2>/dev/null

# Set secure file permissions
echo "[+] Setting secure permissions on sensitive files..."
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow 2>/dev/null
chmod 600 /etc/ssh/sshd_config

# Check for common backdoor accounts
echo "[+] Checking for suspicious accounts..."
SUSPICIOUS=("backdoor" "hacker" "test" "guest" "admin")
for user in "${SUSPICIOUS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "[!] FOUND SUSPICIOUS USER: $user"
    fi
done

echo "========================================="
echo "QUICK HARDENING COMPLETE"
echo "Backups stored in: $BACKUP_DIR"
echo "========================================="
```
