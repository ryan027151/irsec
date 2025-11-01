#!/bin/bash

# Initial script to block all red team activity using firewalld for Rocky Linux

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# --- Configuration ---
# Add your team's IP addresses to this list.
# Example: WHITELISTED_IPS=("192.168.1.100" "10.0.0.5")
WHITELISTED_IPS=("172.16.17.1" "172.16.17.2")

# Duration in seconds to keep the firewall rules active (e.g., 600 for 10 minutes)
BLOCK_DURATION=30

# --- Firewall Setup (firewalld) ---

if ! command -v firewall-cmd &> /dev/null; then
    echo "[!] firewalld command not found. This script is for RHEL-based systems like Rocky Linux."
    exit 1
fi

echo "[+] Starting firewalld service..."
systemctl start firewalld

# Save the current default zone to restore it later
ORIGINAL_DEFAULT_ZONE=$(firewall-cmd --get-default-zone)
echo "[+] Current default zone is '$ORIGINAL_DEFAULT_ZONE'. It will be restored later."

# Create a new zone for the block
echo "[+] Creating a temporary 'block' zone..."
firewall-cmd --new-zone=block --permanent
firewall-cmd --permanent --zone=block --set-target=DROP
firewall-cmd --reload

echo "[+] Setting default zone to 'block' to deny all traffic..."
firewall-cmd --set-default-zone=block
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Set default firewall zone to 'block'" >> /root/activity_log.txt


echo "[+] Whitelisting Blue Team IP addresses in the 'trusted' zone..."
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "    - Allowing all traffic from $ip"
    firewall-cmd --zone=trusted --add-source="$ip"
    echo "$(TZ='America/New_York' date) $(basename \"$0\") - Whitelisted IP for all traffic: $ip" >> /root/activity_log.txt
done

# Ensure loopback traffic is handled by the trusted zone
firewall-cmd --zone=trusted --add-interface=lo &>/dev/null

echo -e "\n[+] Firewall is now active. All non-whitelisted traffic is blocked."
echo "[+] This configuration will be reverted in $BLOCK_DURATION seconds at $(date -d "+$BLOCK_DURATION seconds")"

sleep $BLOCK_DURATION

# --- Firewall Teardown (firewalld) ---
echo -e "\n[+] Reverting firewall rules..."

# Remove whitelisted IPs
for ip in "${WHITELISTED_IPS[@]}"; do
    firewall-cmd --zone=trusted --remove-source="$ip" &>/dev/null
done

# Restore the original default zone
echo "[+] Restoring default zone to '$ORIGINAL_DEFAULT_ZONE'..."
firewall-cmd --set-default-zone="$ORIGINAL_DEFAULT_ZONE"
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Restored default firewall zone to '$ORIGINAL_DEFAULT_ZONE'" >> /root/activity_log.txt

# Remove the temporary block zone
echo "[+] Removing temporary 'block' zone..."
firewall-cmd --delete-zone=block --permanent
firewall-cmd --reload
echo "$(TZ='America/New_York' date) $(basename \"$0\") - Removed temporary 'block' zone" >> /root/activity_log.txt

echo "[+] Firewall rules have been reset. Normal connectivity restored."
