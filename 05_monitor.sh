if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

LOGFILE="/root/monitor_$(date +%Y%m%d_%H%M%S).log"
ALERT_FILE="/root/ALERTS.txt"
BASELINE_USERS="/tmp/baseline_users.txt"
BASELINE_CRON="/tmp/baseline_cron.txt"
BASELINE_PROCS="/tmp/baseline_procs.txt"

echo "========================================="
echo "CONTINUOUS MONITORING STARTED"
echo "Log file: $LOGFILE"
echo "Alert file: $ALERT_FILE"
echo "Press Ctrl+C to stop"
echo "========================================="

# Create baselines
cat /etc/passwd > "$BASELINE_USERS"
crontab -l 2>/dev/null > "$BASELINE_CRON"
ps aux > "$BASELINE_PROCS"

while true; do
    echo "=== Monitor Check: $(date) ===" >> "$LOGFILE"
    
    # Check for new users
    if ! diff -q /etc/passwd "$BASELINE_USERS" &>/dev/null; then
        echo "[ALERT] $(date): USER CHANGE DETECTED" | tee -a "$ALERT_FILE"
        diff /etc/passwd "$BASELINE_USERS" >> "$ALERT_FILE"
        cat /etc/passwd > "$BASELINE_USERS"
    fi
    
    # Check for cron changes
    crontab -l 2>/dev/null > /tmp/current_cron.txt
    if ! diff -q /tmp/current_cron.txt "$BASELINE_CRON" &>/dev/null; then
        echo "[ALERT] $(date): CRON JOB CHANGE" | tee -a "$ALERT_FILE"
        diff /tmp/current_cron.txt "$BASELINE_CRON" >> "$ALERT_FILE"
        cp /tmp/current_cron.txt "$BASELINE_CRON"
    fi
    
    # Check active connections
    CONNECTIONS=$(ss -tupn 2>/dev/null | grep ESTAB | wc -l)
    echo "Active connections: $CONNECTIONS" >> "$LOGFILE"
    ss -tupn 2>/dev/null | grep ESTAB >> "$LOGFILE"
    
    # Check for suspicious processes
    ps aux | grep -E 'nc|ncat|netcat|/bin/sh -i|/bin/bash -i|perl.*socket|python.*socket' | grep -v grep >> "$LOGFILE"
    
    # Check listening ports
    echo "Listening ports:" >> "$LOGFILE"
    ss -tulpn 2>/dev/null >> "$LOGFILE"
    
    # Check for unauthorized sudo usage
    grep "sudo:" /var/log/auth.log 2>/dev/null | tail -5 >> "$LOGFILE"
    
    # Check disk usage
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ $DISK_USAGE -gt 90 ]; then
        echo "[ALERT] $(date): DISK USAGE HIGH: $DISK_USAGE%" | tee -a "$ALERT_FILE"
    fi
    
    echo "---" >> "$LOGFILE"
    
    if [ -f "$ALERT_FILE" ] && [ $(wc -l < "$ALERT_FILE") -gt 0 ]; then
        echo -e "\n!!! CHECK $ALERT_FILE FOR ALERTS !!!\n"
    fi
    
    sleep 60
done

