# Docker httpd on Rocky Linux 9

- [ ] List running containers

```bash
docker ps
```

- [ ] Get in the shell for a running container

```bash
docker exec -it <container_id> /bin/bash
```

- After running the above command for httpd (Apache server), you'll get into a debian-based system from rocky.
- You can install `vim` using `apt update && apt install -y vim` on docker to mess around with the files
- The working directory should be set to the apache server directory, with things like
    - `htdocs/`: The root of the web server content
    - `logs/`: The logs of the web server

- [ ] List server files

```bash
ls /usr/local/apache2/htdocs/
```

- [ ] Make sure that logs are there (access logs)

```apache
# Add the following to httpd.conf
CustomLog "logs/access_log" combined
```

```bash
docker restart <container_id>
```
