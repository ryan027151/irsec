#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "========================================="
echo "QUICK HARDENING - $(date)"
echo "========================================="

# Detect which server this is based on services
echo -e "${YELLOW}[*] Detecting server type...${NC}"
SERVER_TYPE="unknown"

if systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb; then
    SERVER_TYPE="mysql"
    echo -e "${GREEN}[+] Detected: MySQL Server (Big Bang)${NC}"
elif systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then
    SERVER_TYPE="apache"
    echo -e "${GREEN}[+] Detected: Apache Web Server (Chernobyl)${NC}"
elif systemctl is-active --quiet vsftpd || systemctl is-active --quiet proftpd; then
    SERVER_TYPE="ftp"
    echo -e "${GREEN}[+] Detected: FTP Server (Enlightenment)${NC}"
elif systemctl is-active --quiet smbd; then
    SERVER_TYPE="smb"
    echo -e "${GREEN}[+] Detected: Samba Server (Wright Brothers)${NC}"
else
    # Check for SSH-only server
    if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
        SERVER_TYPE="ssh"
        echo -e "${GREEN}[+] Detected: SSH Server (Viking Raids)${NC}"
    fi
fi

echo ""
read -p "Is this detection correct? Press Enter to continue or Ctrl+C to abort: "

# Collect teammate IPs
echo ""
echo "[*] Enter IP addresses for your 3 teammates (one at a time)"
echo "[*] Press Enter after each IP. Leave blank and press Enter when done."
echo ""

TEAMMATE_IPS=()
for i in 1 2 3; do
    read -p "Teammate $i IP address: " ip
    if [ -n "$ip" ]; then
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
[ -f /etc/vsftpd.conf ] && cp /etc/vsftpd.conf "$BACKUP_DIR/"
[ -f /etc/samba/smb.conf ] && cp /etc/samba/smb.conf "$BACKUP_DIR/"
[ -f /etc/mysql/my.cnf ] && cp /etc/mysql/my.cnf "$BACKUP_DIR/"

# Enable and configure firewall with service-specific rules
echo "[+] Configuring firewall for $SERVER_TYPE server..."

if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH from teammate IPs
    for ip in "${TEAMMATE_IPS[@]}"; do
        ufw allow from "$ip" to any port 22 proto tcp comment "Teammate SSH"
        echo "[+] UFW: Allowed SSH from $ip"
    done
    
    # Allow SSH from localhost
    ufw allow from 127.0.0.1 to any port 22
    
    # Service-specific rules
    case $SERVER_TYPE in
        mysql)
            echo "[+] Opening MySQL port 3306..."
            ufw allow 3306/tcp comment 'MySQL'
            ;;
        apache)
            echo "[+] Opening Apache ports 80 and 443..."
            ufw allow 80/tcp comment 'HTTP'
            ufw allow 443/tcp comment 'HTTPS'
            ;;
        ftp)
            echo "[+] Opening FTP ports..."
            ufw allow 21/tcp comment 'FTP'
            ufw allow 20/tcp comment 'FTP Data'
            ufw allow 40000:50000/tcp comment 'FTP Passive'
            ;;
        smb)
            echo "[+] Opening Samba ports..."
            ufw allow 139/tcp comment 'SMB'
            ufw allow 445/tcp comment 'SMB'
            ufw allow 137/udp comment 'NetBIOS'
            ufw allow 138/udp comment 'NetBIOS'
            ;;
        ssh)
            echo "[+] SSH-only server - no additional ports"
            ;;
        *)
            echo "[!] Unknown server type - only SSH allowed"
            ;;
    esac
    
    ufw reload
    echo "UFW firewall enabled with $SERVER_TYPE-specific rules"
    
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --set-default-zone=public
    
    # Allow SSH from teammate IPs
    for ip in "${TEAMMATE_IPS[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' port port='22' protocol='tcp' accept"
        echo "[+] Firewalld: Allowed SSH from $ip"
    done
    
    # Service-specific rules
    case $SERVER_TYPE in
        mysql)
            firewall-cmd --permanent --add-service=mysql
            ;;
        apache)
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            ;;
        ftp)
            firewall-cmd --permanent --add-service=ftp
            ;;
        smb)
            firewall-cmd --permanent --add-service=samba
            ;;
    esac
    
    firewall-cmd --reload
    echo "Firewalld enabled with $SERVER_TYPE-specific rules"
    
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
    
    # Service-specific rules
    case $SERVER_TYPE in
        mysql)
            iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
            ;;
        apache)
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            ;;
        ftp)
            iptables -A INPUT -p tcp --dport 20:21 -j ACCEPT
            iptables -A INPUT -p tcp --dport 40000:50000 -j ACCEPT
            ;;
        smb)
            iptables -A INPUT -p tcp --dport 139 -j ACCEPT
            iptables -A INPUT -p tcp --dport 445 -j ACCEPT
            iptables -A INPUT -p udp --dport 137:138 -j ACCEPT
            ;;
    esac
    
    echo "Basic iptables rules applied with $SERVER_TYPE-specific rules"
    
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > "$BACKUP_DIR/iptables_rules"
    fi
fi

# Save teammate IPs and server type for reference
echo "[+] Saving configuration..."
cat > /root/server_config.txt << EOF
# Server Configuration - Created $(date)
# Server Type: $SERVER_TYPE
# Your IP: $MY_IP
# Teammate IPs:
EOF

for ip in "${TEAMMATE_IPS[@]}"; do
    echo "$ip" >> /root/server_config.txt
done
echo "Configuration saved to /root/server_config.txt"

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
RISKY_SERVICES=("telnet" "rsh" "rlogin")

# Don't disable services we're actually using
case $SERVER_TYPE in
    ftp)
        # Keep FTP services
        ;;
    *)
        RISKY_SERVICES+=("vsftpd" "pure-ftpd" "proftpd")
        ;;
esac

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
SUSPICIOUS=("backdoor" "hacker" "test" "guest" "admin" "redteam")
for user in "${SUSPICIOUS[@]}"; do
    if [ "$user" == "whiteteam" ]; then
        continue
    fi
    if id "$user" &>/dev/null; then
        echo "[!] FOUND SUSPICIOUS USER: $user"
    fi
done

echo "========================================="
echo "QUICK HARDENING COMPLETE"
echo "Server Type: $SERVER_TYPE"
echo "Backups stored in: $BACKUP_DIR"
echo "Team IPs whitelisted: ${#TEAMMATE_IPS[@]}"
echo "Configuration: /root/server_config.txt"
echo "========================================="
