# Linux Hardening Methodology

- [ ] Update and upgrade the system

```bash
sudo apt update && sudo apt upgrade -y
```

- [ ] Enable firewall to block connections

```bash
sudo apt install ufw
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

- [ ] List all the services

```bash
systemctl list-units --type=service --state=running
```

- [ ] Check for open ports

```bash
sudo netstat -tulpn
```
