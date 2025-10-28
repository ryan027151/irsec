```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

EVIDENCE_DIR="/root/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "========================================="
echo "EVIDENCE COLLECTION - $(date)"
echo "Evidence directory: $EVIDENCE_DIR"
echo "========================================="

# Memory dump
echo "[+] Capturing running processes..."
ps auxf > "$EVIDENCE_DIR/processes.txt"
pstree -p > "$EVIDENCE_DIR/process_tree.txt"

# Network state
echo "[+] Capturing network state..."
ss -tupn > "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null || netstat -tupn > "$EVIDENCE_DIR/network_connections.txt"
ss -tulpn > "$EVIDENCE_DIR/listening_ports.txt" 2>/dev/null || netstat -tulpn > "$EVIDENCE_DIR/listening_ports.txt"
ip addr > "$EVIDENCE_DIR/ip_addresses.txt"
ip route > "$EVIDENCE_DIR/routing_table.txt"
arp -a > "$EVIDENCE_DIR/arp_cache.txt" 2>/dev/null

# User state
echo "[+] Capturing user information..."
cp /etc/passwd "$EVIDENCE_DIR/"
cp /etc/shadow "$EVIDENCE_DIR/" 2>/dev/null
cp /etc/group "$EVIDENCE_DIR/"
who > "$EVIDENCE_DIR/logged_in_users.txt"
w > "$EVIDENCE_DIR/user_activity.txt"
last -50 > "$EVIDENCE_DIR/last_logins.txt"
lastlog > "$EVIDENCE_DIR/last_log.txt"

# Copy critical logs
echo "[+] Copying log files..."
mkdir -p "$EVIDENCE_DIR/logs"
cp /var/log/auth.log* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/secure* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/syslog* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/messages* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp -r /var/log/apache2 "$EVIDENCE_DIR/logs/" 2>/dev/null
cp -r /var/log/nginx "$EVIDENCE_DIR/logs/" 2>/dev/null

# Scheduled tasks
echo "[+] Capturing scheduled tasks..."
crontab -l > "$EVIDENCE_DIR/root_crontab.txt" 2>/dev/null
cp /etc/crontab "$EVIDENCE_DIR/" 2>/dev/null
ls -laR /etc/cron.* > "$EVIDENCE_DIR/cron_directories.txt" 2>/dev/null
systemctl list-timers --all > "$EVIDENCE_DIR/systemd_timers.txt" 2>/dev/null

# File system
echo "[+] Capturing file system information..."
df -h > "$EVIDENCE_DIR/disk_usage.txt"
mount > "$EVIDENCE_DIR/mounted_filesystems.txt"
find / -type f -mtime -1 2>/dev/null > "$EVIDENCE_DIR/recently_modified_files.txt"
find / -type f -perm -4000 2>/dev/null > "$EVIDENCE_DIR/suid_files.txt"

# Services
echo "[+] Capturing service information..."
systemctl list-units --type=service > "$EVIDENCE_DIR/services.txt" 2>/dev/null
service --status-all > "$EVIDENCE_DIR/services_status.txt" 2>/dev/null

# Kernel modules
echo "[+] Capturing kernel modules..."
lsmod > "$EVIDENCE_DIR/kernel_modules.txt"

# Environment
echo "[+] Capturing environment..."
env > "$EVIDENCE_DIR/environment.txt"

# Capture bash histories
echo "[+] Capturing command histories..."
mkdir -p "$EVIDENCE_DIR/histories"
for home in /home/* /root; do
    if [ -f "$home/.bash_history" ]; then
        cp "$home/.bash_history" "$EVIDENCE_DIR/histories/$(basename $home)_bash_history" 2>/dev/null
    fi
done

# Package information
echo "[+] Capturing package information..."
dpkg -l > "$EVIDENCE_DIR/installed_packages.txt" 2>/dev/null || rpm -qa > "$EVIDENCE_DIR/installed_packages.txt" 2>/dev/null

# Create evidence manifest
echo "[+] Creating manifest..."
{
    echo "Evidence Collection Report"
    echo "Collected: $(date)"
    echo "Hostname: $(hostname)"
    echo "Collected by: $(whoami)"
    echo ""
    echo "Files collected:"
    find "$EVIDENCE_DIR" -type f -exec ls -lh {} \;
} > "$EVIDENCE_DIR/MANIFEST.txt"

# Create tarball
echo "[+] Creating evidence archive..."
tar czf "${EVIDENCE_DIR}.tar.gz" "$EVIDENCE_DIR" 2>/dev/null

echo "========================================="
echo "EVIDENCE COLLECTION COMPLETE"
echo "Directory: $EVIDENCE_DIR"
echo "Archive: ${EVIDENCE_DIR}.tar.gz"
echo "========================================="
```
