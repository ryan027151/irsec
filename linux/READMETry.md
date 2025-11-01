```markdown
# Optimized IRSec Competition Routine for Linux Machines

## Overview
This toolkit helps you **find problems**, **fix them fast**, and **watch for attacks** on Linux systems during the IRSec competition.

**Core Functions:**
1. **Find Problems** - Check system config, users, network, hidden files
2. **Fix Problems** - Enable firewall, harden SSH, rotate passwords
3. **Watch for Attacks** - Monitor for new users, cron jobs, suspicious processes
4. **Stop Attacks** - Log incidents, capture evidence, analyze logs

---

## Pre-Competition Setup

### On Your Prep Laptop
```bash
mkdir -p competition_toolkit/linux_scripts
cd competition_toolkit/linux_scripts
git clone https://github.com/ryan027151/irsec.git
```

### File Structure
```
Your Laptop
└── competition_toolkit/
    ├── linux_scripts/      ← All Linux .sh files
    └── windows_scripts/    ← All Windows .ps1 files
```

---

## Competition Day - Initial Setup (First 5 Minutes)

### Both Fedora and Ubuntu

**1. Upload toolkit to both machines**
```bash
# Transfer via SCP or USB
scp -r linux_scripts/ user@target-machine:~/

# Then on target machine:
sudo mv ~/linux_scripts /root/toolkit
cd /root/toolkit
```

**2. Make scripts executable**
```bash
chmod +x *.sh
```

**3. Ubuntu Only: Start SSH (if not running)**
```bash
sudo systemctl status ssh
sudo systemctl start ssh
sudo systemctl enable ssh
sudo ss -tlnp | grep :22
```

**4. Ubuntu Only: Install Required Packages**
```bash
sudo apt update
sudo apt install auditd jq -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

**5. Initial Security (Run on BOTH machines)**
```bash
sudo ./01_enum.sh              # Know your system - review output carefully
sudo ./02_quick_harden.sh      # Lock it down - firewall, SSH, whitelist team IPs
sudo ./03_rotate_passwords.sh  # Change ALL passwords (SAVE THE PASSWORD!)
sudo ./04_user_audit.sh        # Check for unauthorized users
```

⚠️ **CRITICAL:** 
- When running `02_quick_harden.sh`, you'll be prompted to enter your 3 teammates' IPs
- Save the new password from `03_rotate_passwords.sh` and share with your team immediately!
- The script saves team IPs to `/root/team_ips.txt` for reference

---

## After Network is Secured (Next 10 Minutes)

### Fedora (MySQL Server)
```bash
# Secure MySQL
sudo ./12_harden_mysql.sh

# Start continuous monitoring (runs in background)
sudo ./05_monitor.sh &

# Verify monitoring is running
jobs

# Run initial threat hunt
sudo ./06_threat_hunt.sh
```

### Ubuntu (Wazuh Server)

#### Step 1: Install Wazuh (if not already installed)
```bash
# Download and run Wazuh installer
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Save the admin credentials displayed at the end!
# Access Wazuh at: https://<ubuntu-ip>
```

#### Step 2: Configure Wazuh for Team Environment
```bash
# 1. Change Wazuh admin password via web interface
# - Navigate to https://<ubuntu-ip>
# - Login with credentials from installation
# - Go to Settings → Security → Internal users → admin → Edit
# - Set a strong password and share with team

# 2. Configure firewall to allow only team access
sudo ufw allow from TEAM_IP_1 to any port 443 comment "Teammate 1 Wazuh"
sudo ufw allow from TEAM_IP_2 to any port 443 comment "Teammate 2 Wazuh"
sudo ufw allow from TEAM_IP_3 to any port 443 comment "Teammate 3 Wazuh"
```

#### Step 3: Deploy Wazuh Agents on Other Machines

**On Fedora (MySQL Server):**
```bash
# Download Wazuh agent
curl -so wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm

# Install and configure
sudo WAZUH_MANAGER='<ubuntu-wazuh-ip>' rpm -ihv wazuh-agent.rpm

# Start agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

**On Windows Machines:**
- Download agent from Wazuh dashboard: Settings → Agents → Deploy new agent
- Follow Windows-specific installation instructions
- Register with Ubuntu Wazuh server IP

#### Step 4: Setup Automated Threat Response
```bash
# Copy automated response scripts to Wazuh directory
sudo cp /root/toolkit/auto_threat_hunt.sh /var/ossec/active-response/bin/
sudo cp /root/toolkit/auto_capture_evidence.sh /var/ossec/active-response/bin/
sudo cp /root/toolkit/auto_block_backdoor.sh /var/ossec/active-response/bin/

# Set correct permissions
sudo chmod 750 /var/ossec/active-response/bin/auto_*.sh
sudo chown root:wazuh /var/ossec/active-response/bin/auto_*.sh

# Verify files are in place
ls -la /var/ossec/active-response/bin/auto_*.sh
```

#### Step 5: Configure Wazuh Manager for Active Response
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this configuration **before** the closing `</ossec_config>` tag:

```xml
<!-- Active Response Commands -->
<command>
  <name>auto-threat-hunt</name>
  <executable>auto_threat_hunt.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>auto-capture-evidence</name>
  <executable>auto_capture_evidence.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>auto-block-backdoor</name>
  <executable>auto_block_backdoor.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Trigger threat hunt on SSH brute force attacks -->
<active-response>
  <command>auto-threat-hunt</command>
  <location>local</location>
  <rules_id>5710,5712</rules_id>
</active-response>

<!-- Trigger threat hunt on high severity alerts (level 12+) -->
<active-response>
  <command>auto-threat-hunt</command>
  <location>local</location>
  <level>12</level>
</active-response>

<!-- Auto-capture evidence on critical alerts (level 15+) -->
<active-response>
  <command>auto-capture-evidence</command>
  <location>local</location>
  <level>15</level>
</active-response>

<!-- Auto-block on web shell detection -->
<active-response>
  <command>auto-block-backdoor</command>
  <location>local</location>
  <rules_id>31153,31154</rules_id>
</active-response>
```

Save and exit (Ctrl+O, Enter, Ctrl+X)

#### Step 6: Restart Wazuh and Verify
```bash
# Restart Wazuh manager
sudo systemctl restart wazuh-manager

# Check status
sudo systemctl status wazuh-manager

# Verify active response is loaded
sudo tail -f /var/ossec/logs/ossec.log | grep -i "active-response"

# Check if agents are connected
sudo /var/ossec/bin/wazuh-control info
```

#### Step 7: Configure Wazuh Dashboard Monitoring

**Access Dashboard:** Navigate to `https://<ubuntu-ip>` in browser

**Essential Views to Monitor:**
1. **Security Events** → Real-time alerts from all agents
2. **Integrity Monitoring** → File changes across systems
3. **Vulnerability Detection** → CVEs on monitored systems
4. **Security Configuration Assessment** → Compliance checks
5. **Threat Hunting** → Custom queries for IOCs

**Create Custom Dashboard:**
```
1. Go to Dashboards → Create new dashboard
2. Add these visualizations:
   - Failed SSH attempts (last 1 hour)
   - Top 10 security alerts by severity
   - File integrity changes
   - Network connections to unusual ports
   - User account changes
   - Web server attacks (if applicable)
3. Save as "Competition Monitor"
```

**Setup Alert Forwarding (Optional but Recommended):**
```bash
# Configure email alerts for critical events
sudo nano /var/ossec/etc/ossec.conf
```

Add email configuration:
```xml
<global>
  <email_notification>yes</email_notification>
  <email_to>team@example.com</email_to>
  <smtp_server>smtp.example.com</smtp_server>
  <email_from>wazuh@competition.local</email_from>
</global>

<email_alerts>
  <email_to>team@example.com</email_to>
  <level>12</level>
  <do_not_delay/>
</email_alerts>
```

#### Step 8: Enable Local Monitoring on Ubuntu
```bash
# Start continuous monitoring
sudo ./05_monitor.sh &

# Run initial threat hunt
sudo ./06_threat_hunt.sh

# Verify threat hunt results
sudo ls -la /root/threat_hunt_*.txt
```

---

## Throughout Competition (Continuous Operations)

### Every 30 Minutes - Manual Threat Hunt
```bash
# On BOTH Fedora and Ubuntu
sudo /root/toolkit/06_threat_hunt.sh

# Review the output file
sudo cat /root/threat_hunt_*.txt | less
```

### Continuous Wazuh Dashboard Monitoring (Ubuntu)

**Assign one team member to monitor Wazuh dashboard continuously:**

1. **Every 5 Minutes:** Check Security Events for new alerts
2. **Every 15 Minutes:** Review File Integrity Monitoring for unauthorized changes
3. **Every 30 Minutes:** Check agent status (ensure all agents are connected)
4. **On Any Alert Level 12+:** Investigate immediately and notify team

**Key Alerts to Watch For:**
- Multiple failed SSH attempts (brute force)
- New user accounts created
- SUID/SGID file modifications
- Suspicious cron jobs added
- Web shell uploads
- Unusual network connections
- Service configuration changes
- File modifications in /etc/, /bin/, /sbin/

**Using Wazuh Threat Hunting:**
```
1. Go to Tools → API Console
2. Run queries to search for specific IOCs:

# Search for specific IP connections
GET /security_events?q=data.srcip:<suspicious-ip>

# Find all authentication failures
GET /security_events?rule.groups=authentication_failed

# Search for web attacks
GET /security_events?rule.groups=web,attack
```

### If Incident Detected

**Immediate Response (on affected machine):**
```bash
# Log the incident
sudo /root/toolkit/08_log_incident.sh

# Capture evidence
sudo /root/toolkit/09_capture_evidence.sh

# View incident reports
sudo cat /root/incidents.txt
sudo ls -la /root/incidents/
```

**On Wazuh Dashboard (Ubuntu):**
1. Navigate to affected agent
2. Check Security Events for timeline of attack
3. Review File Integrity changes
4. Export evidence: Tools → Reporting → Generate report
5. Document findings in incident log

**Team Coordination:**
```bash
# Share incident details with team
sudo cat /root/incidents/incident_*.txt

# If attacker persists, consider isolating the system
sudo ufw deny from <attacker-ip> to any
# or via Wazuh active response (automatic if configured)
```

---

## Wazuh Advanced Configuration

### Custom Rules for Competition Scenarios

**Create custom detection rules:**
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add competition-specific rules:
```xml
<group name="local,syslog,">
  <!-- Detect suspicious sudo usage -->
  <rule id="100001" level="10">
    <if_sid>5401</if_sid>
    <match>sudo</match>
    <description>Suspicious sudo command executed</description>
  </rule>

  <!-- Detect reverse shell attempts -->
  <rule id="100002" level="15">
    <match>/bin/bash -i|/bin/sh -i|nc -e|ncat -e</match>
    <description>Possible reverse shell detected</description>
  </rule>

  <!-- Detect password changes -->
  <rule id="100003" level="8">
    <match>password changed for</match>
    <description>User password was changed</description>
  </rule>

  <!-- Detect new cron jobs -->
  <rule id="100004" level="10">
    <match>crontab.*installed</match>
    <description>New crontab entry added</description>
  </rule>
</group>
```

Restart Wazuh:
```bash
sudo systemctl restart wazuh-manager
```

### Monitor Specific Files

**Add critical files to integrity monitoring:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add to `<syscheck>` section:
```xml
<syscheck>
  <!-- Monitor web directories -->
  <directories check_all="yes" realtime="yes">/var/www</directories>
  <directories check_all="yes" realtime="yes">/usr/share/nginx</directories>
  
  <!-- Monitor system configs -->
  <directories check_all="yes" realtime="yes">/etc/ssh</directories>
  <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
  <directories check_all="yes" realtime="yes">/etc/crontab</directories>
  
  <!-- Monitor user directories -->
  <directories check_all="yes" realtime="yes">/home/*/. ssh</directories>
  <directories check_all="yes" realtime="yes">/root/.ssh</directories>
</syscheck>
```

### Performance Tuning for Competition

**Optimize Wazuh for fast response:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Adjust these settings:
```xml
<global>
  <!-- Faster alert processing -->
  <email_alert_level>12</email_alert_level>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
  
  <!-- More frequent scans -->
  <frequency>60</frequency>
</global>

<syscheck>
  <!-- Check files every 5 minutes instead of default -->
  <frequency>300</frequency>
  <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
</syscheck>
```

---

## Quick Reference Commands

### Check Background Jobs
```bash
jobs                    # List running background jobs
fg                      # Bring job to foreground
bg                      # Resume job in background
kill %1                 # Kill job number 1
```

### Stop Monitoring Script
```bash
sudo killall 05_monitor.sh
```

### View Logs
```bash
# System logs
sudo tail -f /var/log/auth.log           # Authentication logs (Ubuntu)
sudo tail -f /var/log/secure             # Authentication logs (Fedora)
sudo tail -f /var/log/syslog             # System logs
sudo journalctl -f                       # Real-time system journal

# Wazuh logs
sudo tail -f /var/ossec/logs/ossec.log                    # Wazuh manager
sudo tail -f /var/ossec/logs/active-responses.log         # Active response actions
sudo tail -f /var/ossec/logs/alerts/alerts.log            # All alerts
```

### Access Root Files
```bash
sudo ls -la /root/                       # List root directory
sudo cat /root/incidents.txt             # View all incidents
sudo ls -la /root/incidents/             # List incident files
sudo cat /root/team_ips.txt              # View whitelisted team IPs
```

### Wazuh Agent Management
```bash
# List all connected agents
sudo /var/ossec/bin/agent_control -l

# Check specific agent status
sudo /var/ossec/bin/agent_control -i <agent-id>

# Restart agent (on agent machine)
sudo systemctl restart wazuh-agent

# View agent logs (on agent machine)
sudo tail -f /var/ossec/logs/ossec.log
```

### Manual Threat Response
```bash
# Block an IP immediately
sudo ufw insert 1 deny from <attacker-ip> to any

# Kill a suspicious process
sudo kill -9 <PID>

# Disable a compromised user
sudo usermod -L <username>
sudo passwd -l <username>

# Remove suspicious cron jobs
sudo crontab -e        # For current user
sudo crontab -u <user> -e   # For specific user
```

---

## Team Assignments

| Person | Machine | Primary Responsibilities |
|--------|---------|--------------------------|
| Person 1 | Windows DC | AD security, user management, GPO hardening |
| Person 2 | Windows App | Application security, IIS/services hardening |
| Person 3 | Fedora MySQL | Database security, SQL injection monitoring |
| Person 4 | Ubuntu Wazuh | **SIEM monitoring, coordinate team response, central logging** |

**Person 4 (Wazuh Operator) Should:**
- Keep Wazuh dashboard open at all times
- Alert team immediately on Level 12+ alerts
- Coordinate incident response across all systems
- Monitor agent connectivity
- Review threat hunt results from all machines
- Export evidence when incidents occur

---

## Common Issues & Fixes

### "Permission denied" when running script
```bash
chmod +x script.sh
sudo ./script.sh
```

### "Command not found" with sudo
```bash
sudo bash ./script.sh    # Run with bash explicitly
```

### Can't access /root/
```bash
sudo su                  # Switch to root
cd /root
# Or prefix commands with sudo
```

### SSH connection refused
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
sudo ufw allow 22
sudo ss -tlnp | grep :22
```

### Script has no output
- Check if file is empty: `cat script.sh`
- Remove markdown backticks if present (```bash)
- Ensure shebang is `#!/bin/bash` not `#!/bin/sh`
- Run with: `sudo bash script.sh`

### Wazuh agent not connecting
```bash
# On agent machine, check configuration
sudo cat /var/ossec/etc/ossec.conf | grep address

# Restart agent
sudo systemctl restart wazuh-agent

# Check logs
sudo tail -f /var/ossec/logs/ossec.log

# On Wazuh server, check firewall
sudo ufw allow 1514/tcp   # Agent communication
sudo ufw allow 1515/tcp   # Agent enrollment
```

### Wazuh dashboard not accessible
```bash
# Check if services are running
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-indexer

# Check firewall
sudo ufw status
sudo ufw allow 443

# Restart all Wazuh services
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
```

### Active response not triggering
```bash
# Verify scripts are in place
ls -la /var/ossec/active-response/bin/auto_*.sh

# Check permissions
sudo chmod 750 /var/ossec/active-response/bin/auto_*.sh
sudo chown root:wazuh /var/ossec/active-response/bin/auto_*.sh

# Verify configuration
sudo grep -A 5 "auto-threat-hunt" /var/ossec/etc/ossec.conf

# Check logs
sudo tail -f /var/ossec/logs/active-responses.log

# Test manually
echo '{"parameters":{"alert":{"id":"12345","rule":{"level":"12"}}}}' | sudo /var/ossec/active-response/bin/auto_threat_hunt.sh
```

---

## Critical Reminders

✅ **Save the new password** from `03_rotate_passwords.sh` - share with all teammates!  
✅ **Whitelist team IPs** in `02_quick_harden.sh` - verify all 3 teammates can access  
✅ **Run threat hunts every 30 minutes** on both Fedora and Ubuntu  
✅ **Monitor Wazuh dashboard continuously** - assign one person full-time  
✅ **Document all incidents immediately** using `08_log_incident.sh`  
✅ **Keep `05_monitor.sh` running in background** on both machines  
✅ **Test SSH access** before competition starts  
✅ **Verify all Wazuh agents are connected** before competition starts  
✅ **Export Wazuh credentials** and save securely  
✅ **Test active response** by triggering a test alert  

---

## Pre-Competition Checklist

### Fedora MySQL Server
- [ ] Toolkit uploaded to `/root/toolkit`
- [ ] All scripts executable (`chmod +x *.sh`)
- [ ] SSH enabled and accessible
- [ ] Team IPs whitelisted in firewall
- [ ] MySQL secured with `12_harden_mysql.sh`
- [ ] Monitoring script running (`05_monitor.sh &`)
- [ ] Wazuh agent installed and connected
- [ ] Initial threat hunt completed
- [ ] Password rotated and saved

### Ubuntu Wazuh Server
- [ ] Toolkit uploaded to `/root/toolkit`
- [ ] All scripts executable (`chmod +x *.sh`)
- [ ] SSH enabled and accessible
- [ ] `auditd` and `jq` installed
- [ ] Team IPs whitelisted in firewall
- [ ] Wazuh installed and accessible via HTTPS
- [ ] Wazuh admin password changed and saved
- [ ] Active response scripts installed
- [ ] Wazuh configuration updated with active response
- [ ] Wazuh manager restarted
- [ ] All agents connected and reporting
- [ ] Custom dashboard created
- [ ] Monitoring script running (`05_monitor.sh &`)
- [ ] Initial threat hunt completed
- [ ] Password rotated and saved

### Team Coordination
- [ ] All teammates have Wazuh dashboard credentials
- [ ] All teammates know the new system passwords
- [ ] Communication channel established (Slack/Discord/etc.)
- [ ] Roles assigned (who monitors Wazuh, who handles incidents, etc.)
- [ ] Incident response procedure reviewed
- [ ] Emergency contacts saved

---

## Competition Strategy

### Time Allocation
- **0-5 min:** Initial hardening (firewall, SSH, passwords)
- **5-10 min:** Service-specific hardening (MySQL, Wazuh setup)
- **10-15 min:** Verify all systems, test connectivity
- **15+ min:** Continuous monitoring and threat hunting

### Response Priority
1. **Critical (Level 15):** Drop everything, investigate immediately
2. **High (Level 12-14):** Investigate within 5 minutes
3. **Medium (Level 8-11):** Review during next threat hunt cycle
4. **Low (Level 1-7):** Review at end of competition if time permits

### Team Communication
- **Wazuh operator** is the central point - alerts entire team on critical findings
- Use short, clear messages: "Fedora - SSH brute force - IP 10.x.x.x - investigating"
- Document everything in incident logs
- Share passwords/credentials securely (not in plain text chat)

### Winning Mindset
- **Speed matters:** First 15 minutes are critical
- **Documentation matters:** Log all incidents for scoring
- **Persistence matters:** Attackers will try multiple times
- **Communication matters:** Keep team informed
- **Wazuh is your superpower:** Use it aggressively

---

## Additional Resources

- **Wazuh Documentation:** https://documentation.wazuh.com/
- **Linux Hardening Guide:** https://madaidans-insecurities.github.io/guides/linux-hardening.html
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework

---

**Good luck! Remember: The team that communicates best and uses Wazuh most effectively usually wins! 🏆**
```
