
```bash
#!/bin/bash

INCIDENT_LOG="/root/incidents.txt"
INCIDENT_DIR="/root/incidents"
mkdir -p "$INCIDENT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INCIDENT_FILE="$INCIDENT_DIR/incident_$TIMESTAMP.txt"

echo "========================================="
echo "INCIDENT LOGGER"
echo "========================================="

{
echo "========================================="
echo "INCIDENT REPORT"
echo "Timestamp: $(date)"
echo "========================================="

read -p "Incident Title/Summary: " title
echo "Title: $title"

read -p "Severity (Low/Medium/High/Critical): " severity
echo "Severity: $severity"

read -p "Affected System/Service: " affected
echo "Affected: $affected"

read -p "Description of incident: " description
echo "Description: $description"

read -p "Attack vector (if known): " vector
echo "Attack Vector: $vector"

read -p "Actions taken: " actions
echo "Actions Taken: $actions"

echo ""
echo "=== SYSTEM STATE CAPTURE ==="
echo "Captured at: $(date)"

echo -e "\n=== Current Users ==="
who

echo -e "\n=== User Accounts ==="
cat /etc/passwd

echo -e "\n=== Active Processes (top 30) ==="
ps auxf | head -30

echo -e "\n=== Network Connections ==="
ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null

echo -e "\n=== Listening Ports ==="
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

echo -e "\n=== Recent Auth Log Entries ==="
tail -50 /var/log/auth.log 2>/dev/null || tail -50 /var/log/secure 2>/dev/null

echo -e "\n=== Cron Jobs ==="
crontab -l 2>/dev/null

echo -e "\n=== Recent Commands (bash history) ==="
history | tail -50

echo -e "\n=== Disk Usage ==="
df -h

echo -e "\n=== Memory Usage ==="
free -h

echo -e "\n=== Load Average ==="
uptime

echo ""
echo "========================================="
echo "END INCIDENT REPORT"
echo "========================================="

} | tee "$INCIDENT_FILE"

echo "" >> "$INCIDENT_LOG"
cat "$INCIDENT_FILE" >> "$INCIDENT_LOG"

echo ""
echo "Incident logged to:"
echo "  - $INCIDENT_FILE"
echo "  - $INCIDENT_LOG"
echo ""
```
