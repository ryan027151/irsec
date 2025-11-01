#!/bin/bash
# File: /var/ossec/active-response/bin/auto_threat_hunt.sh
# Wazuh Active Response wrapper for automated threat hunting

# Directory where scripts are located
SCRIPT_DIR="/root/toolkit"

# Read Wazuh alert parameters (JSON format)
read INPUT_JSON

# Parse alert details (requires jq, but handle if not available)
if command -v jq &> /dev/null; then
    ALERT_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.id // "unknown"')
    ALERT_LEVEL=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.level // "unknown"')
else
    ALERT_ID="unknown"
    ALERT_LEVEL="unknown"
fi

# Log the trigger
LOG_FILE="/var/ossec/logs/active-responses.log"
echo "$(date '+%Y-%m-%d %H:%M:%S'): Wazuh triggered threat hunt - Alert: $ALERT_ID Level: $ALERT_LEVEL" >> "$LOG_FILE"

# Run threat hunting script
if [ -f "$SCRIPT_DIR/06_threat_hunt.sh" ]; then
    cd "$SCRIPT_DIR" || exit 1
    bash ./06_threat_hunt.sh >> "$LOG_FILE" 2>&1
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Threat hunt completed" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ERROR - 06_threat_hunt.sh not found at $SCRIPT_DIR" >> "$LOG_FILE"
    exit 1
fi

# Optionally capture evidence on high-severity alerts
if [ "$ALERT_LEVEL" -ge 12 ] 2>/dev/null; then
    if [ -f "$SCRIPT_DIR/09_capture_evidence.sh" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): High severity alert - capturing evidence" >> "$LOG_FILE"
        bash "$SCRIPT_DIR/09_capture_evidence.sh" >> "$LOG_FILE" 2>&1
    fi
fi

exit 0
