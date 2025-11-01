#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

INVENTORY_FILE="/root/network_inventory_$(date +%Y%m%d_%H%M%S).txt"

echo "========================================="
echo "NETWORK INVENTORY COLLECTION"
echo "$(date)"
echo "========================================="

{
echo "========================================="
echo "COMPREHENSIVE NETWORK INVENTORY"
echo "Generated: $(date)"
echo "========================================="
echo ""

# ==========================================
# 1. SYSTEM INFORMATION
# ==========================================
echo "========================================="
echo "1. SYSTEM INFORMATION"
echo "========================================="

echo ""
echo "--- Hostname & IP Address ---"
HOSTNAME=$(hostname)
IP_ADDRESS=$(hostname -I | awk '{print $1}')
FQDN=$(hostname -f 2>/dev/null || echo "N/A")

echo "Hostname: $HOSTNAME"
echo "IP Address: $IP_ADDRESS"
echo "FQDN: $FQDN"
echo ""

echo "--- Operating System ---"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "OS: $NAME"
    echo "Version: $VERSION"
    echo "ID: $ID"
else
    echo "OS: $(uname -s)"
    echo "Kernel: $(uname -r)"
fi
echo "Architecture: $(uname -m)"
echo "Kernel Version: $(uname -r)"
echo ""

echo "--- System Uptime ---"
uptime
echo ""

# ==========================================
# 2. LEGITIMATE USERS
# ==========================================
echo ""
echo "========================================="
echo "2. LEGITIMATE USERS"
echo "========================================="

echo ""
echo "--- All Human Users (UID >= 1000) ---"
echo "Username          UID    Shell              Home Directory"
echo "----------------------------------------------------------------"
awk -F: '$3 >= 1000 && $1 != "nobody" {printf "%-15s   %-6s %-18s %s\n", $1, $3, $7, $6}' /etc/passwd

echo ""
echo "--- Users with Root Privileges (UID 0) ---"
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo ""
echo "--- Users with Sudo Access ---"
grep -Po '^sudo.+:\K.*$' /etc/group 2>/dev/null || echo "No sudo group found"
if [ -f /etc/sudoers ]; then
    echo ""
    echo "Sudoers file entries:"
    grep -v '^#' /etc/sudoers | grep -v '^$' | head -20
fi

echo ""
echo "--- Recently Logged In Users ---"
lastlog | head -20

echo ""
echo "--- Currently Logged In Users ---"
who
echo ""
w

# ==========================================
# 3. NETWORK CONFIGURATION
# ==========================================
echo ""
echo "========================================="
echo "3. NETWORK CONFIGURATION"
echo "========================================="

echo ""
echo "--- Network Interfaces ---"
ip addr show

echo ""
echo "--- Routing Table ---"
ip route show

echo ""
echo "--- DNS Configuration ---"
echo "DNS Servers:"
cat /etc/resolv.conf 2>/dev/null

echo ""
echo "--- Hosts File ---"
cat /etc/hosts

echo ""
echo "--- Network Connections Summ
