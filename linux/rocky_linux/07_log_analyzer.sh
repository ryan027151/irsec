#!/bin/bash

LOGFILE="${1:-/var/log/secure}"

if [ ! -f "$LOGFILE" ]; then
    # Fallback for Debian-based systems
    if [ -f /var/log/auth.log ]; then
        LOGFILE="/var/log/auth.log"
    else
        echo "Log file not found: $LOGFILE or /var/log/auth.log"
        echo "Usage: $0 [logfile]"
        exit 1
    fi
fi

echo "========================================="
echo "LOG ANALYSIS - $(date)"
echo "$(TZ='America/New_York' date) $(basename "$0") - Log analysis script started for $LOGFILE" >> /root/activity_log.txt
echo "Analyzing: $LOGFILE"
echo "========================================="

OUTPUT="log_analysis_$(basename $LOGFILE)_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== LOG ANALYSIS REPORT ==="
echo "File: $LOGFILE"
echo "Date: $(date)"
echo ""

echo "=== FAILED LOGIN ATTEMPTS ==="
grep -i "failed password" "$LOGFILE" | tail -50

echo -e "\n=== FAILED LOGIN SUMMARY BY IP ==="
grep -i "failed password" "$LOGFILE" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -rn | head -20

echo -e "\n=== SUCCESSFUL LOGINS ==="
grep -i "accepted password\|accepted publickey" "$LOGFILE" | tail -30

echo -e "\n=== ROOT LOGIN ATTEMPTS ==="
grep -i "root" "$LOGFILE" | grep -i "failed\|accepted" | tail -30

echo -e "\n=== SUDO USAGE ==="
grep -i "sudo:" "$LOGFILE" | tail -30

echo -e "\n=== USER CREATION/DELETION ==="
grep -iE "useradd|userdel|adduser" "$LOGFILE"

echo -e "\n=== PRIVILEGE ESCALATION ATTEMPTS ==="
grep -i "su:" "$LOGFILE" | tail -20

echo -e "\n=== SSH KEY USAGE ==="
grep -i "publickey" "$LOGFILE" | tail -20

echo -e "\n=== INVALID USERS ==="
grep -i "invalid user" "$LOGFILE" | tail -30

echo -e "\n=== BREAK-IN ATTEMPTS ==="
grep -i "break-in attempt\|possible break-in" "$LOGFILE"

echo -e "\n=== SESSION OPENED/CLOSED ==="
grep -i "session opened\|session closed" "$LOGFILE" | tail -20

} | tee "$OUTPUT"

# Web log analysis
if [ -f /var/log/httpd/access.log ] || [ -f /var/log/nginx/access.log ] || [ -f /var/log/apache2/access.log ]; then
    echo -e "\n=== WEB LOG ANALYSIS ==="
    
    WEBLOG=""
    if [ -f /var/log/httpd/access.log ]; then
        WEBLOG="/var/log/httpd/access.log"
    elif [ -f /var/log/nginx/access.log ]; then
        WEBLOG="/var/log/nginx/access.log"
    elif [ -f /var/log/apache2/access.log ]; then
        WEBLOG="/var/log/apache2/access.log"
    fi
    
    {
    echo -e "\n=== TOP 20 IPs ==="
    awk '{print $1}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    echo -e "\n=== SQL INJECTION ATTEMPTS ==="
    grep -iE "union.*select|concat.*\(|script.*>|<script|'; drop|' or '1'='1" "$WEBLOG" | tail -30
    
    echo -e "\n=== DIRECTORY TRAVERSAL ATTEMPTS ==="
    grep -E "\.\./|\.\.%2[fF]" "$WEBLOG" | tail -20
    
    echo -e "\n=== SUSPICIOUS USER AGENTS ==="
    grep -iE "nikto|nmap|sqlmap|burp|metasploit|nessus|masscan|acunetix" "$WEBLOG" | tail -20
    
    echo -e "\n=== FILE UPLOAD ATTEMPTS ==="
    grep -iE "\.php|\.asp|\.jsp|\.cgi" "$WEBLOG" | grep POST | tail -20
    
    echo -e "\n=== 404 ERRORS (recon) ==="
    awk '$9 == 404 {print $7}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    echo -e "\n=== 500 ERRORS (exploitation?) ==="
    awk '$9 ~ /^5/ {print $7}' "$WEBLOG" | sort | uniq -c | sort -rn | head -20
    
    } | tee -a "$OUTPUT"
fi

echo "========================================="
echo "LOG ANALYSIS COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="
