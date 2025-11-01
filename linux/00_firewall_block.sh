#!/bin/bash
# Initial script to block all red team activity with interactive IP whitelisting

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# --- Configuration ---
# Load existing team IPs from previous hardening script if available
if [ -f /root/team_ips.txt ]; then
    echo -e "${GREEN}[+] Loading teammate IPs from /root/team_ips.txt${NC}"
    WHITELISTED_IPS=($(grep -v "^#" /root/team_ips.txt | grep -v "^$"))
else
    # Default whitelist - add your team's IP addresses here
    WHITELISTED_IPS=("172.16.17.1" "172.16.17.2")
fi

# Display current whitelist
echo "========================================="
echo "FIREWALL EMERGENCY BLOCK"
echo "========================================="
echo -e "${YELLOW}Current whitelisted IPs (teammates):${NC}"
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "  - $ip"
done
echo ""

# Ask if user wants to add more IPs
echo -e "${YELLOW}[?] Do you want to add more IPs to the whitelist?${NC}"
echo "    (Enter IP addresses one at a time, press Enter with no input when done)"
echo ""

ADDITIONAL_IPS=()
while true; do
    read -p "Enter IP to whitelist (or press Enter to continue): " new_ip
    
    # If empty input, break the loop
    if [ -z "$new_ip" ]; then
        break
    fi
    
    # Basic IP validation
    if [[ $new_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Check if IP is already in the list
        if [[ " ${WHITELISTED_IPS[@]} " =~ " ${new_ip} " ]] || [[ " ${ADDITIONAL_IPS[@]} " =~ " ${new_ip} " ]]; then
            echo -e "    ${YELLOW}[!] IP $new_ip is already whitelisted${NC}"
        else
            ADDITIONAL_IPS+=("$new_ip")
            echo -e "    ${GREEN}[+] Added: $new_ip${NC}"
        fi
    else
        echo -e "    ${RED}[!] Invalid IP format, skipping...${NC}"
    fi
done

# Merge additional IPs into whitelist
if [ ${#ADDITIONAL_IPS[@]} -gt 0 ]; then
    echo ""
    echo -e "${GREEN}[+] Added ${#ADDITIONAL_IPS[@]} new IP(s) to whitelist${NC}"
    WHITELISTED_IPS+=("${ADDITIONAL_IPS[@]}")
    
    # Save updated whitelist to file
    echo "# Updated whitelist - $(date)" > /root/firewall_whitelist.txt
    for ip in "${WHITELISTED_IPS[@]}"; do
        echo "$ip" >> /root/firewall_whitelist.txt
    done
    echo -e "${GREEN}[+] Whitelist saved to /root/firewall_whitelist.txt${NC}"
else
    echo -e "${YELLOW}[*] No additional IPs added${NC}"
fi

echo ""
echo -e "${YELLOW}Final whitelist:${NC}"
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "  - $ip"
done
echo ""

# Confirm before blocking
read -p "Proceed with firewall lockdown? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Duration in seconds to keep the firewall rules active
echo ""
read -p "Enter block duration in seconds (default 30, press Enter for default): " duration_input
BLOCK_DURATION=${duration_input:-30}

echo ""
echo "========================================="
echo "ACTIVATING EMERGENCY FIREWALL BLOCK"
echo "Duration: $BLOCK_DURATION seconds"
echo "========================================="

# --- Firewall Setup (UFW) ---
echo -e "${RED}[+] Resetting ufw to a clean state...${NC}"
ufw --force reset
echo "$(TZ='America/New_York' date) $(basename "$0") - Firewall reset to clean state (emergency block)" >> /root/activity_log.txt

echo -e "${RED}[+] Setting default policies to DENY...${NC}"
ufw default deny incoming
echo "$(TZ='America/New_York' date) $(basename "$0") - Set default firewall policy to deny incoming (emergency)" >> /root/activity_log.txt
ufw default deny outgoing
echo "$(TZ='America/New_York' date) $(basename "$0") - Set default firewall policy to deny outgoing (emergency)" >> /root/activity_log.txt

echo -e "${GREEN}[+] Allowing loopback traffic...${NC}"
ufw allow in on lo
echo "$(TZ='America/New_York' date) $(basename "$0") - Allowed incoming loopback traffic" >> /root/activity_log.txt
ufw allow out on lo
echo "$(TZ='America/New_York' date) $(basename "$0") - Allowed outgoing loopback traffic" >> /root/activity_log.txt

echo -e "${GREEN}[+] Whitelisting team IP addresses...${NC}"
for ip in "${WHITELISTED_IPS[@]}"; do
    echo "    - Allowing all traffic from/to $ip"
    ufw allow from "$ip"
    echo "$(TZ='America/New_York' date) $(basename "$0") - Whitelisted IP for all traffic: $ip" >> /root/activity_log.txt
    ufw allow to "$ip"
    echo "$(TZ='America/New_York' date) $(basename "$0") - Whitelisted outgoing to IP: $ip" >> /root/activity_log.txt
done

echo -e "${RED}[+] Enabling firewall...${NC}"
ufw --force enable
echo "$(TZ='America/New_York' date) $(basename "$0") - Firewall enabled with emergency block (${#WHITELISTED_IPS[@]} IPs whitelisted)" >> /root/activity_log.txt

echo ""
echo "========================================="
echo -e "${RED}[!] FIREWALL IS NOW IN LOCKDOWN MODE${NC}"
echo "    All non-whitelisted traffic is BLOCKED"
echo "    Whitelisted IPs: ${#WHITELISTED_IPS[@]}"
echo "    This will auto-revert in $BLOCK_DURATION seconds"
echo "    Revert time: $(date -d "+$BLOCK_DURATION seconds")"
echo "========================================="
echo ""
echo -e "${YELLOW}Press Ctrl+C to cancel auto-revert (firewall will stay locked)${NC}"
echo ""

# Countdown timer
for ((i=BLOCK_DURATION; i>0; i--)); do
    if [ $i -le 10 ] || [ $((i % 10)) -eq 0 ]; then
        echo "    Time remaining: ${i}s"
    fi
    sleep 1
done

# --- Firewall Teardown (UFW) ---
echo ""
echo "========================================="
echo -e "${GREEN}[+] Block duration expired - reverting firewall...${NC}"
echo "========================================="

ufw disable
echo "$(TZ='America/New_York' date) $(basename "$0") - Firewall disabled after emergency block duration" >> /root/activity_log.txt

ufw --force reset
echo "$(TZ='America/New_York' date) $(basename "$0") - All firewall rules reset after emergency block" >> /root/activity_log.txt

echo -e "${GREEN}[+] Firewall has been disabled and reset.${NC}"
echo -e "${GREEN}[+] Normal connectivity restored.${NC}"
echo ""
echo "To re-enable normal security firewall, run: sudo ./02_quick_harden.sh"
