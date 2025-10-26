Simple Summary of What the Script Does
The script is a set of tools to find problems, fix them fast, and watch for attacks on a Linux computer.

Broken Down by Main Goal:

Find Problems (Enumeration & Audit): It quickly checks the system's setup, users, network connections, and hidden files to find weak spots or signs of a previous attack.

Fix Problems (Hardening & Passwords): It immediately secures the system by setting up a firewall, strengthening the SSH login settings, and changing all user passwords to a single secure one.

Watch for Attacks (Monitoring & Hunting): It runs continuous checks for new users, changed tasks (cron jobs), and suspicious programs, and regularly hunts for signs of malicious activity like web shells or reverse shells.

Stop Attacks (Incident Response): If an attack happens, it has tools to record the details, capture important system files and data (evidence), and analyze logs for attack patterns.

# On your prep laptop, create the toolkit
mkdir -p linux_toolkit/{phase1_initial,phase2_continuous,phase3_incident,service_specific,utilities}

# Copy all scripts into the appropriate folders
# Then upload to BOTH machines:
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
# after initially securing the network #
```sh
cd /root/toolkit/service_specific
sudo ./12_harden_mysql.sh      # Secure MySQL

cd /root/toolkit/phase2_continuous
sudo ./05_monitor.sh &         # Start monitoring in background
sudo ./06_threat_hunt.sh       # Hunt for threats
```
# Throughout competition #
```sh
 ** Run threat hunt every 30 minutes **
sudo ./06_threat_hunt.sh

 ** If an incident happens: **
cd /root/toolkit/phase3_incident
sudo ./08_log_incident.sh
```
