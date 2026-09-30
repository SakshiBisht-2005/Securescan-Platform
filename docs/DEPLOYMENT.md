# Linux Production Deployment (no Docker)

Target stack: Django (Gunicorn) + Nginx + MySQL + Redis + Celery, all
running directly on the host via systemd.

## 1. System packages

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential \
  libmysqlclient-dev pkg-config mysql-server redis-server nginx
```

## 2. Application user & code

```bash
sudo useradd -m -s /bin/bash securescan
sudo -u securescan -H bash -c '
  cd ~
  git clone <your-repo-url> securescan-app
  cd securescan-app/backend
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  pip install gunicorn
'
```

## 3. Database

```bash
sudo mysql <<'SQL'
CREATE DATABASE securescan CHARACTER SET utf8mb4;
CREATE USER 'securescan_user'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG';
GRANT ALL PRIVILEGES ON securescan.* TO 'securescan_user'@'localhost';
FLUSH PRIVILEGES;
SQL
```

## 4. Environment

```bash
sudo -u securescan cp /home/securescan/securescan-app/backend/.env.example \
  /home/securescan/securescan-app/backend/.env
sudo -u securescan nano /home/securescan/securescan-app/backend/.env
# Set: DEBUG=False, SECRET_KEY=<random 50+ char value>, DATABASE_*,
# REDIS_URL=redis://localhost:6379/0, ALLOWED_HOSTS=your.domain.com,
# CORS_ALLOWED_ORIGINS=https://your.domain.com
```

## 5. Migrate & collect static files

```bash
sudo -u securescan -H bash -c '
  cd ~/securescan-app/backend && source venv/bin/activate
  python manage.py makemigrations
  python manage.py migrate
  python manage.py createsuperuser
  python manage.py collectstatic --noinput
'
```

## 6. systemd unit: Gunicorn

`/etc/systemd/system/securescan-gunicorn.service`

```ini
[Unit]
Description=SecureScan Gunicorn
After=network.target mysql.service redis-server.service

[Service]
User=securescan
Group=securescan
WorkingDirectory=/home/securescan/securescan-app/backend
Environment="PATH=/home/securescan/securescan-app/backend/venv/bin"
ExecStart=/home/securescan/securescan-app/backend/venv/bin/gunicorn \
  config.wsgi:application \
  --bind 127.0.0.1:8000 \
  --workers 3 \
  --timeout 120 \
  --access-logfile /home/securescan/securescan-app/backend/logs/gunicorn-access.log \
  --error-logfile /home/securescan/securescan-app/backend/logs/gunicorn-error.log
Restart=always

[Install]
WantedBy=multi-user.target
```

## 7. systemd unit: Celery worker

`/etc/systemd/system/securescan-celery.service`

```ini
[Unit]
Description=SecureScan Celery Worker
After=network.target redis-server.service

[Service]
User=securescan
Group=securescan
WorkingDirectory=/home/securescan/securescan-app/backend
Environment="PATH=/home/securescan/securescan-app/backend/venv/bin"
ExecStart=/home/securescan/securescan-app/backend/venv/bin/celery \
  -A config worker --loglevel=info --concurrency=2
Restart=always

[Install]
WantedBy=multi-user.target
```

## 7b. systemd unit: Celery beat (weekly scans)

`/etc/systemd/system/securescan-celery-beat.service`

```ini
[Unit]
Description=SecureScan Celery Beat
After=network.target redis-server.service

[Service]
User=securescan
Group=securescan
WorkingDirectory=/home/securescan/securescan-app/backend
Environment="PATH=/home/securescan/securescan-app/backend/venv/bin"
ExecStart=/home/securescan/securescan-app/backend/venv/bin/celery \
  -A config beat --loglevel=info \
  --pidfile=/home/securescan/securescan-app/backend/logs/celerybeat.pid \
  --schedule=/home/securescan/securescan-app/backend/logs/celerybeat-schedule
Restart=always

[Install]
WantedBy=multi-user.target
```

## 8. Enable and start services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now securescan-gunicorn securescan-celery securescan-celery-beat
sudo systemctl status securescan-gunicorn securescan-celery securescan-celery-beat
```

## 9. Nginx

`/etc/nginx/sites-available/securescan`

```nginx
server {
    listen 80;
    server_name your.domain.com;

    client_max_body_size 220M;  # match MAX_UPLOAD_SIZE_MB with headroom

    location /static/ {
        alias /home/securescan/securescan-app/backend/staticfiles/;
    }
    location /media/ {
        alias /home/securescan/securescan-app/backend/media/;
        # Reports live under media/reports/ - consider an auth_request
        # subrequest here in front of Nginx if you serve them directly
        # instead of via the authenticated /api/reports/{id}/download/ view.
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /django-admin/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }

    # Frontend static files
    root /home/securescan/securescan-app/frontend;
    location / {
        try_files $uri $uri.html $uri/ =404;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/securescan /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Then put TLS in front of it (e.g. `certbot --nginx`) — production should
never serve the API or frontend over plain HTTP.

## 10. Post-deploy checklist

- [ ] `DEBUG=False`, real `SECRET_KEY`, `ALLOWED_HOSTS` set correctly
- [ ] `SECURE_SSL_REDIRECT` on (default when `DEBUG=False`) once TLS is live
- [ ] MySQL user has only the privileges it needs on the `securescan` DB
- [ ] Redis bound to localhost / protected by firewall, not exposed publicly
- [ ] `logs/`, `media/`, `scan_temp/` are writable by the `securescan` user
      and excluded from version control
- [ ] Optional scanners installed per `docs/SCANNERS.md` if you want their
      broader coverage in production
- [ ] A cron/systemd timer (or Celery beat) periodically calls
      `cleanup_scan_files` to sweep orphaned temp directories
