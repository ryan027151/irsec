# Linux Hardening Methodology

- [ ] Update and upgrade the system

```bash
sudo apt update && sudo apt upgrade -y
```

## Firewall
- [ ] Enable firewall to block connections

```bash
sudo apt install ufw
sudo ufw default deny
sudo ufw allow ssh
sudo ufw enable
```

- [ ] List all the services

```bash
systemctl list-units --type=service --state=running
```

- [ ] Check for open ports

```bash
sudo netstat -tulpn
```

## Secure MySQL

```bash
sudo mysql_secure_installation

# to enter mysql
sudo mysql
```

Upon running the above command, set the following things
    - Validate password plugin: Y
    - Password policy: 2 (strong)
    - Remove anonymous users: Y
    - Disallow root login remotely: Y
    - Remove test database: Y
    - Reload privilege tables: Y

To check the users
```sql
SELECT user, host, plugin, authentication_string from mysql.user;
```

Make sure that

- The `plugin` for root says `auth_socket`
    - This means that mysql root can be only access from system root user, and not `mysql -u root -p`
- The `host` column
    - `%`: Remote login allowed
    - `localhost`/`127.0.0.1`: Local login only

To remove a user

```sql
DROP USER 'username'@'host';
-- DROP USER 'pentester'@'%';
```

To rename a host

```sql
RENAME USER 'your_user'@'%' TO 'your_user'@'localhost';
```
