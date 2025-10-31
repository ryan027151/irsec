#!/bin/bash

# Initial script to block all red team activity

# --- Configuration ---
# Add your team's IP addresses to this list.
# Example: WHITELISTED_IPS=("192.168.1.100" "10.0.0.5")
WHITELISTED_IPS=("172.16.17.1")

# Duration in seconds to keep the firewall rules active (e.g., 600 for 10 minutes)
BLOCK_DURATION=600

# --- Firewall Setup (UFW) ---
echo "[+] Resetting ufw to a clean state..."
ufw --force reset

echo "[+] Setting default policies to DENY..."
ufw default deny incoming
ufw default deny outgoing

echo "[+] Allowing loopback traffic..."
ufw allow in on lo
ufw allow out on lo

echo "[+] Whitelisting Blue Team IP addresses..."
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "    - Allowing all traffic from/to $ip"
    ufw allow from "$ip"
    ufw allow to "$ip"
done

echo "[+] Enabling firewall..."
ufw enable

echo -e "\n[+] Firewall is now active. All non-whitelisted traffic is blocked."
echo "[+] This configuration will be reverted in $BLOCK_DURATION seconds at $(date -d "+$BLOCK_DURATION seconds")"

sleep $BLOCK_DURATION

# --- Firewall Teardown (UFW) ---
echo -e "\n[+] Disabling firewall and reverting rules..."
ufw disable
ufw --force reset

echo "[+] Firewall has been disabled and reset. Normal connectivity restored."