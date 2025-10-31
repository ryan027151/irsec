# File: /var/ossec/active-response/bin/auto_threat_hunt.sh
#!/bin/bash
# Wazuh Active Response wrapper

LOCAL=$(dirname $0)
SCRIPT_DIR="/root/toolkit"

# Read Wazuh alert parameters
read INPUT_JSON
ALERT_ID=$(echo $INPUT_JSON | jq -r '.parameters.alert.id')
ALERT_LEVEL=$(echo $INPUT_JSON | jq -r '.parameters.alert.rule.level')

# Log the trigger
echo "$(date): Wazuh triggered threat hunt - Alert: $ALERT_ID Level: $ALERT_LEVEL" >> /var/ossec/logs/active-responses.log
echo "$(date) $(basename "$0") - Wazuh triggered auto threat hunt (Alert: $ALERT_ID, Level: $ALERT_LEVEL)" >> /root/activity_log.txt

# Run threat hunting script
cd $SCRIPT_DIR/phase2_continuous
./06_threat_hunt.sh

# Optionally capture evidence
cd $SCRIPT_DIR/phase3_incident
./09_capture_evidence.sh

exit 0
