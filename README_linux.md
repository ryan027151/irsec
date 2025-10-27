Simple Summary of What the Script Does
The script is a set of tools to find problems, fix them fast, and watch for attacks on a Linux computer.

Broken Down by Main Goal:

1. Find Problems (Enumeration & Audit): It quickly checks the system's setup, users, network connections, and hidden files to find weak spots or signs of a previous attack.

2. Fix Problems (Hardening & Passwords): It immediately secures the system by setting up a firewall, strengthening the SSH login settings, and changing all user passwords to a single secure one.

3. Watch for Attacks (Monitoring & Hunting): It runs continuous checks for new users, changed tasks (cron jobs), and suspicious programs, and regularly hunts for signs of malicious activity like web shells or reverse shells.

4. Stop Attacks (Incident Response): If an attack happens, it has tools to record the details, capture important system files and data (evidence), and analyze logs for attack patterns.

# On your prep laptop, create the toolkit
```sh
mkdir -p linux_toolkit/{phase1_initial,phase2_continuous,phase3_incident,service_specific,utilities}
```

**Copy all scripts into the appropriate folders**
# Upload to BOTH machines:
```sh
scp -r linux_toolkit/ root@fedora-server:/root/
scp -r linux_toolkit/ root@ubuntu-wazuh:/root/
```

## Fedora in first 5 min ##
```sh
cd /root/toolkit/phase1_initial
sudo ./01_enum.sh              # Know your system
sudo ./02_quick_harden.sh      # Lock it down
sudo ./03_rotate_passwords.sh  # Change passwords
sudo ./04_user_audit.sh        # Check users
```
# After initially securing the network #
```sh
cd /root/toolkit/service_specific
sudo ./12_harden_mysql.sh      # Secure MySQL

cd /root/toolkit/phase2_continuous
sudo ./05_monitor.sh &         # Start monitoring in background
sudo ./06_threat_hunt.sh       # Hunt for threats
```
# Throughout competition #
```sh
#Run threat hunt every 30 minutes
sudo ./06_threat_hunt.sh

 ** If an incident happens: **
cd /root/toolkit/phase3_incident
sudo ./08_log_incident.sh
```
___
## Ubantu in first 5 min ##
```sh
cd /root/toolkit/phase1_initial
sudo ./01_enum.sh              # Know your system
sudo ./02_quick_harden.sh      # Lock it down
sudo ./03_rotate_passwords.sh  # Change passwords
sudo ./04_user_audit.sh        # Check users
```
# After initially securing the network #
```sh
cd /root/toolkit/phase2_continuous
sudo ./05_monitor.sh &         # Start monitoring in background
sudo ./06_threat_hunt.sh       # Hunt for threats

# Also secure Wazuh itself:
# Change Wazuh admin password via web interface
# Configure firewall to only allow your team IPs to access Wazuh dashboard
```
# Throughout competition #
```sh
# Use Wazuh dashboard to monitor alerts from all systems
# Run threat hunts locally on this machine too
sudo ./06_threat_hunt.sh

# If incident happens:
cd /root/toolkit/phase3_incident
sudo ./08_log_incident.sh
```

## **Think of It Like This:**
Your Team = 4 people

Person 1: Windows DC machine → needs Windows scripts
Person 2: Windows App machine → needs Windows scripts  
Person 3: Fedora MySQL machine → needs Linux scripts
Person 4: Ubuntu Wazuh machine → needs Linux scripts

**Before Competition:**
```
Your Laptop
└── competition_toolkit/
    ├── linux_scripts/          ← All Linux .sh files
    │   ├── phase1_initial/
    │   ├── phase2_continuous/
    │   ├── phase3_incident/
    │   ├── service_specific/
    │   └── utilities/
    └── windows_scripts/        ← All Windows .ps1 files
        ├── phase1_initial/
        ├── phase2_continuous/
        ├── phase3_incident/
        ├── service_specific/
        └── utilities/
```

**During Competition (after uploading):**
```
Fedora Server                Ubuntu Wazuh Server
/root/toolkit/               /root/toolkit/
├── phase1_initial/          ├── phase1_initial/
├── phase2_continuous/       ├── phase2_continuous/
├── phase3_incident/         ├── phase3_incident/
├── service_specific/        ├── service_specific/
└── utilities/               └── utilities/
```
___
**To make Wasuh automattcially activate script**
```sh
# Make the wazuh script executable
chmod 750 /var/ossec/active-response/bin/auto_threat_hunt.sh
chown root:wazuh /var/ossec/active-response/bin/auto_threat_hunt.sh
```
