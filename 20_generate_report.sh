
#!/bin/bash

OUTPUT="FINAL_INCIDENT_REPORT_$(date +%Y%m%d_%H%M%S).md"

echo "$(TZ='America/New_York' date) $(basename "$0") - Report generation script started" >> /root/activity_log.txt
cat > "$OUTPUT" << 'EOF'
# INCIDENT RESPONSE REPORT
## IRSeC Competition

**Date:** [Competition Date]  
**Team:** [Your Team Name]  
**Team Members:** [List all members]  
**Report Prepared By:** [Your Name]

---

## EXECUTIVE SUMMARY

[Provide a brief 2-3 paragraph overview of the competition, major incidents encountered, and overall team performance]

---

## SYSTEM INVENTORY

### Systems Under Our Control

| System | IP Address | OS | Role | Services |
|--------|------------|----|----- |----------|
| System 1 | 10.0.0.1 | Ubuntu 20.04 | Web Server | Apache, MySQL |
| System 2 | 10.0.0.2 | Windows Server 2019 | Domain Controller | AD, DNS |
| System 3 | 10.0.0.3 | CentOS 8 | Mail Server | Postfix, Dovecot |
| System 4 | 10.0.0.4 | Windows 10 | Workstation | IIS, SQL Server |

---

## TIMELINE OF EVENTS

### Initial Phase (00:00 - 00:05)

**00:00:30 - System Enumeration**
- Action: Deployed enumeration scripts on all systems
- Findings: Discovered [X] systems, [Y] services running
- Team Member: [Name]

**00:01:00 - Password Rotation**
- Action: Changed all default passwords
- Systems: All 4 systems
- New password documented in secure location
- Team Member: [Name]

**00:02:00 - Firewall Configuration**
- Action: Enabled firewalls on all systems
- Configuration: Default deny inbound, allow essential services
- Team Member: [Name]

**00:03:30 - SSH/RDP Hardening**
- Action: Hardened remote access
- Changes: Disabled root login, limited auth tries, configured timeouts
- Team Member: [Name]

**00:05:00 - Initial Threat Hunt**
- Action: Ran threat hunting scripts
- Findings: [Describe any backdoors found]
- Team Member: [Name]

### Incident 1: [Title] (00:15 - 00:25)

**Discovery:**
- Time: 00:15:23
- How Detected: [Monitoring alert / Log analysis / Manual inspection]
- Initial Indicator: [What tipped you off]

**Investigation:**
- Attack Vector: [How did the attacker get in]
- Affected Systems: [List systems]
- Compromised Accounts: [Any compromised accounts]
- IOCs Identified:
  - IP Addresses: [List suspicious IPs]
  - File Hashes: [If applicable]
  - Suspicious Files: [Paths to malicious files]
  - Processes: [Suspicious process names/PIDs]

**Impact:**
- Confidentiality: [Was data accessed?]
- Integrity: [Were files modified?]
- Availability: [Were services disrupted?]

**Response Actions:**
1. [00:16:00] Isolated affected system from network
2. [00:17:30] Killed malicious process (PID: XXXX)
3. [00:18:00] Removed backdoor user account
4. [00:19:00] Deleted web shell at /var/www/html/shell.php
5. [00:20:00] Changed passwords for all accounts
6. [00:21:00] Restored service
7. [00:22:00] Verified system integrity
8. [00:23:00] Resumed monitoring

**Evidence Collected:**
- Screenshots: [Describe]
- Log excerpts: [Describe]
- Files preserved: [List]

**Lessons Learned:**
- Root Cause: [What vulnerability was exploited]
- Prevention: [How to prevent in future]

### Incident 2: [Title] (00:45 - 01:00)

[Repeat same structure as Incident 1]

### Incident 3: [Title] (01:30 - 01:45)

[Repeat same structure]

---

## INJECT RESPONSES

### Inject 1: [Title]

**Received:** 00:30:00  
**Completed:** 00:42:00  
**Point Value:** 50 points  

**Requirements:**
- [List inject requirements]

**Actions Taken:**
- [Step-by-step what you did]

**Verification:**
- [How you verified completion]
- [Screenshots/evidence]

**Challenges:**
- [Any difficulties encountered]

### Inject 2: [Title]

[Repeat for each inject]

---

## SECURITY MEASURES IMPLEMENTED

### Network Security

**Firewall Configuration:**
- Default deny inbound traffic
- Allow only: SSH (22), HTTP (80), HTTPS (443), DNS (53)
- Egress filtering: Blocked suspicious IPs
- Rate limiting implemented

**Network Monitoring:**
- Continuous monitoring script deployed
- IDS/IPS: [If applicable]
- Traffic analysis performed every 30 minutes

### System Hardening

**Linux Systems:**
- Password policies: 12 character minimum, complexity required
- SSH: Root login disabled, key-based auth encouraged, max 3 auth tries
- Services: Disabled telnet, FTP, unnecessary services
- File permissions: Secured sensitive files (600/644/755)
- Audit logging: Enabled auditd
- Regular updates applied

**Windows Systems:**
- Group Policy: Security baseline applied
- User accounts: Disabled guest, removed unauthorized users
- Services: Disabled unnecessary services
- Windows Firewall: Enabled with restrictive rules
- Audit policies: Enabled for all categories
- Windows Defender: Updated and running

### Application Security

**Web Servers:**
- Removed default pages
- Disabled directory listing
- Hidden server version
- ModSecurity/WAF enabled
- SSL/TLS configured
- Regular web shell scans

**Databases:**
- Changed default passwords
- Removed test databases
- Disabled remote root access
- Query logging enabled
- Least privilege principle applied

**Other Services:**
- DNS: Restricted zone transfers
- Mail: Prevented open relay, SPF/DKIM configured
- FTP: Disabled anonymous access, chroot enabled

---

## INDICATORS OF COMPROMISE (IOCs)

### Network IOCs

| IP Address | Port | First Seen | Activity | Action Taken |
|------------|------|------------|----------|--------------|
| 192.168.1.100 | 4444 | 00:15 | Reverse shell | Blocked at firewall |
| 10.10.10.50 | 80 | 00:45 | SQL injection | Blocked at firewall |

### File IOCs

| File Path | Hash (if available) | Description | Action Taken |
|-----------|---------------------|-------------|--------------|
| /var/www/html/shell.php | - | Web shell | Deleted |
| /tmp/.hidden | - | Backdoor script | Deleted |

### Account IOCs

| Username | System | Description | Action Taken |
|----------|--------|-------------|--------------|
| backdoor | Linux-01 | Unauthorized user | Deleted |
| hacker | Windows-DC | Unauthorized admin | Deleted |

---

## ATTACK PATTERNS OBSERVED

### Attack Pattern 1: SQL Injection
- **Frequency:** [Number of attempts]
- **Target:** Web application login form
- **Success Rate:** 0% (blocked by input validation)
- **Mitigation:** Implemented prepared statements

### Attack Pattern 2: Brute Force SSH
- **Frequency:** [Number of attempts]
- **Target:** All Linux systems
- **Success Rate:** 0% (fail2ban blocked after 3 attempts)
- **Mitigation:** Fail2ban with 3 try limit

[Continue for other patterns]

---

## CHALLENGES ENCOUNTERED

1. **Challenge:** [Describe challenge]
   - **Impact:** [How it affected response]
   - **Resolution:** [How you overcame it]

2. **Challenge:** [Describe challenge]
   - **Impact:** [How it affected response]
   - **Resolution:** [How you overcame it]

---

## RECOMMENDATIONS

### Immediate Actions (If This Were Real)

1. **Password Management**
   - Implement password manager
   - Enforce MFA on all administrative accounts
   - Regular password rotation policy

2. **Network Segmentation**
   - Separate production and admin networks
   - Implement VLANs
   - DMZ for public-facing services

3. **Monitoring and Alerting**
   - Deploy SIEM solution
   - Real-time alerting for critical events
   - Automated incident response playbooks

### Long-Term Improvements

1. **Security Training**
   - Regular security awareness training
   - Phishing simulations
   - Incident response drills

2. **Infrastructure**
   - Upgrade legacy systems
   - Implement security orchestration
   - Regular penetration testing

3. **Documentation**
   - Maintain updated network diagrams
   - Document all security controls
   - Create incident response playbooks

---

## STATISTICS

**Overall Performance:**
- Total Incidents Detected: [X]
- Total Incidents Resolved: [X]
- Average Response Time: [X minutes]
- Injects Completed: [X / Y]
- Points Earned: [Total]

**System Uptime:**
- System 1: [%]
- System 2: [%]
- System 3: [%]
- System 4: [%]

**Attack Statistics:**
- Total Attack Attempts Detected: [X]
- Successful Attacks: [X]
- Blocked Attacks: [X]
- Attack Success Rate: [X%]

---

## CONCLUSION

[2-3 paragraphs summarizing:
- Overall team performance
- Key successes
- Areas for improvement
- Lessons learned
- Final thoughts]

---

## APPENDICES

### Appendix A: Configuration Files
[Include sanitized copies of key configurations]

### Appendix B: Log Excerpts
[Include relevant log entries]

### Appendix C: Screenshots
[Reference evidence screenshots]

### Appendix D: Tools Used
- Enumeration: Custom bash scripts
- Monitoring: Custom monitoring scripts
- Log Analysis: grep, awk, sed
- Network Analysis: ss, netstat, tcpdump
- Web Security: ModSecurity
- Password Security: Automated rotation scripts

---

**Report End**

*This report contains sensitive security information and should be handled accordingly.*
EOF

echo "========================================="
echo "REPORT TEMPLATE GENERATED"
echo "File: $OUTPUT"
echo "========================================="
echo ""
echo "Edit this template and fill in all sections"
echo "during and after the competition."
echo ""
