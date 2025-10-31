
#!/bin/bash

echo "========================================="
echo "NETWORK CONNECTION MONITOR"
echo "$(date) $(basename "$0") - Network connection monitor script started" >> /root/activity_log.txt
echo "Press Ctrl+C to stop"
echo "========================================="

LOGFILE="/root/network_monitor_$(date +%Y%m%d_%H%M%S).log"

while true; do
    clear
    echo "=== NETWORK MONITOR - $(date) ==="
    echo ""
    
    echo "=== ESTABLISHED CONNECTIONS ==="
    ss -tupn 2>/dev/null | grep ESTAB || netstat -tupn 2>/dev/null | grep ESTABLISHED
    
    echo -e "\n=== LISTENING PORTS ==="
    ss -tulpn 2>/dev/null | grep LISTEN || netstat -tulpn 2>/dev/null | grep LISTEN
    
    echo -e "\n=== TOP 10 CONNECTIONS BY IP ==="
    ss -tupn 2>/dev/null | grep ESTAB | awk '{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10 || \
    netstat -tupn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
    
    # Log connections
    echo "=== $(date) ===" >> "$LOGFILE"
    ss -tupn 2>/dev/null >> "$LOGFILE" || netstat -tupn 2>/dev/null >> "$LOGFILE"
    echo "" >> "$LOGFILE"
    
    sleep 5
done
