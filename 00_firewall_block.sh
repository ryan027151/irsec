#!/bin/bash

# Initial script to block all red team activity

# --- Configuration ---
# Add your team's IP addresses to this list.
# Example: WHITELISTED_IPS=("192.168.1.100" "10.0.0.5")
WHITELISTED_IPS=("172.16.17.1" "172.16.17.2")

# Duration in seconds to keep the firewall rules active (e.g., 600 for 10 minutes)
BLOCK_DURATION=30

# --- Firewall Setup (UFW) ---
echo "[+] Resetting ufw to a clean state..."
ufw --force reset
echo "$(date) $(basename \"$0\") - Firewall reset to clean state" >> /root/activity_log.txt

echo "[+] Setting default policies to DENY..."
ufw default deny incoming
echo "$(date) $(basename "$0") - Set default firewall policy to deny incoming" >> /root/activity_log.txt
ufw default deny outgoing
echo "$(date) $(basename "$0") - Set default firewall policy to deny outgoing" >> /root/activity_log.txt

echo "[+] Allowing loopback traffic..."
ufw allow in on lo
echo "$(date) $(basename "$0") - Allowed incoming loopback traffic" >> /root/activity_log.txt
ufw allow out on lo
echo "$(date) $(basename "$0") - Allowed outgoing loopback traffic" >> /root/activity_log.txt

echo "[+] Whitelisting Blue Team IP addresses..."
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "    - Allowing all traffic from/to $ip"
    ufw allow from "$ip"
    echo "$(date) $(basename \"$0\") - Whitelisted IP for all traffic: $ip" >> /root/activity_log.txt
    ufw allow to "$ip"
    echo "$(date) $(basename \"$0\") - Whitelisted IP for all traffic: $ip" >> /root/activity_log.txt
done

echo "[+] Enabling firewall..."
ufw enable
echo "$(date) $(basename "$0") - Firewall enabled with whitelisted IPs" >> /root/activity_log.txt

echo -e "\n[+] Firewall is now active. All non-whitelisted traffic is blocked."
echo "[+] This configuration will be reverted in $BLOCK_DURATION seconds at $(date -d "+$BLOCK_DURATION seconds")"

sleep $BLOCK_DURATION

# --- Firewall Teardown (UFW) ---
echo -e "\n[+] Disabling firewall and reverting rules..."
ufw disable
echo "$(date) $(basename "$0") - Firewall disabled" >> /root/activity_log.txt
ufw --force reset
echo "$(date) $(basename \"$0\") - All firewall rules reset after block duration" >> /root/activity_log.txt

echo "[+] Firewall has been disabled and reset. Normal connectivity restored."