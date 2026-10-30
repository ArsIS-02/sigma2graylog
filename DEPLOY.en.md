# Deployment

**Русская версия: [DEPLOY.md](DEPLOY.md)**

The application is a single container: FastAPI + uvicorn on port 8080, all state in `/data`.
Below are the options, from "look at it in a minute" to production with autostart.

## Which one to pick

| Situation | Option |
|---|---|
| Just want to look, no Graylog yet | [Demo mode](#1-demo-mode-no-graylog) |
| One server, Docker | [`docker run`](#21-docker-run) or [Compose](#22-docker-compose) |
| One server, RHEL / Fedora / RedOS | [Podman + quadlet](#33-autostart-via-systemd-quadlet) |
| You already run a cluster | [Kubernetes / k3s](#4-kubernetes--k3s) |
| Containers not allowed | [venv + systemd](#5-without-a-container-venv--systemd) |
| No internet access | [Offline install](#9-offline-install) |

Minimum requirements: 1 vCPU, 256 MB RAM, 500 MB disk, network access to the Graylog API (usually port 9000).

---

## 1. Demo mode (no Graylog)

Synthetic data: 5 streams, 68 fields, 10 detections. No sign-in — the UI opens immediately.

```bash
docker build -t sigma2graylog:latest https://github.com/ArsIS-02/sigma2graylog.git

docker run -d --name sigma2graylog-demo -p 8080:8080 -e DEMO_MODE=1 sigma2graylog:latest
```

Open `http://localhost:8080`. It is handy to keep a demo instance next to the real one, on another port:

```bash
docker run -d --name sigma2graylog-demo -p 8090:8080 -e DEMO_MODE=1 sigma2graylog:latest
```

Ready-made file: [`docker-compose.demo.yml`](docker-compose.demo.yml).

```bash
docker compose -f docker-compose.demo.yml up -d
```

Demo data is bilingual too: detection and stream names follow the `X-Lang` header, so an English
UI shows English sample content.

---

## 2. Docker

### 2.1. `docker run`

```bash
git clone https://github.com/ArsIS-02/sigma2graylog.git
cd sigma2graylog
docker build -t sigma2graylog:latest .
```

Prepare the environment:

```bash
cp .env.example .env
$EDITOR .env          # GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASSWORD, APP_PASSWORD
```

Run:

```bash
docker run -d --name sigma2graylog \
  --env-file .env \
  -p 8080:8080 \
  -v s2g-data:/data \
  --restart unless-stopped \
  sigma2graylog:latest
```

Why each flag matters:

- `--env-file .env` — all connection settings without rebuilding the image;
- `-v s2g-data:/data` — named volume. Without it, users, settings and saved mappings are lost
  when the container is recreated;
- `--restart unless-stopped` — comes back after a host reboot.

Check:

```bash
docker logs -f sigma2graylog      # expect: Uvicorn running on http://0.0.0.0:8080
curl -s http://localhost:8080/healthz
```

### 2.2. Docker Compose

```bash
cp .env.example .env && $EDITOR .env
docker compose up -d --build
docker compose logs -f
```

[`docker-compose.yml`](docker-compose.yml) already has the volume, a healthcheck and port mapping
(the port is set by `S2G_PORT`).

### 2.3. Upgrading

```bash
git pull
docker compose build
docker compose up -d
```

The `/data` volume is untouched: settings, users and passwords survive.

---

## 3. Podman

Differences from Docker: no daemon, and it can run rootless. The main gotcha is SELinux.

### 3.1. `podman run`

```bash
podman build -t localhost/sigma2graylog:latest .

podman run -d --name sigma2graylog \
  --env-file .env \
  -p 8080:8080 \
  -v s2g-data:/data:Z \
  --restart unless-stopped \
  localhost/sigma2graylog:latest
```

The `:Z` suffix is required on SELinux systems (RedOS, Fedora, RHEL): without it the container
cannot access the directory and the app fails while writing to `/data`.

### 3.2. `podman-compose`

```bash
podman-compose -f podman-compose.yaml up -d
podman-compose -f podman-compose.yaml logs -f
```

### 3.3. Autostart via systemd (quadlet)

For Podman 4.4+ this is the preferred production setup: systemd owns the container, so restart
and boot-time start are its responsibility.

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/sigma2graylog.container ~/.config/containers/systemd/
cp .env.example ~/sigma2graylog.env && $EDITOR ~/sigma2graylog.env

systemctl --user daemon-reload
systemctl --user enable --now sigma2graylog
loginctl enable-linger $USER      # keep running without an active session
```

Managing it:

```bash
systemctl --user status sigma2graylog
journalctl --user -u sigma2graylog -f
systemctl --user restart sigma2graylog
```

The unit already sets `HealthCmd`, `AutoUpdate=registry` and the `s2g-data` volume.
On Podman older than 4.4, use the deprecated but working approach:

```bash
podman generate systemd --new --name sigma2graylog > ~/.config/systemd/user/sigma2graylog.service
systemctl --user daemon-reload && systemctl --user enable --now sigma2graylog
```

### 3.4. SELinux and `/data` permissions

Two cases that break the install most often:

**Bind mount to a host directory.** You need `:Z`:

```bash
mkdir -p /srv/sigma2graylog
podman run -d --name sigma2graylog -p 8080:8080 --env-file .env \
  -v /srv/sigma2graylog:/data:Z localhost/sigma2graylog:latest
```

**The directory was already labelled and `:Z` changes the MCS categories.** On every container
recreation Podman assigns new categories, previously written files become unreadable, the app
cannot find `users.json` and recreates it — the password silently resets to `APP_PASSWORD`.
If that happens, disable labelling for this container:

```bash
podman run -d --name sigma2graylog --security-opt label=disable \
  -p 8080:8080 --env-file .env \
  -v /srv/sigma2graylog:/data localhost/sigma2graylog:latest
```

---

## 4. Kubernetes / k3s

Ready-made manifest: [`deploy/k8s/sigma2graylog.yaml`](deploy/k8s/sigma2graylog.yaml) —
Namespace, Secret, 1 GiB PVC, Deployment, Service and Ingress.

```bash
$EDITOR deploy/k8s/sigma2graylog.yaml    # image, hostname, passwords in the Secret
kubectl apply -f deploy/k8s/sigma2graylog.yaml
kubectl -n sigma2graylog get pods -w
```

Notes:

- always one replica (`strategy: Recreate`): state lives in `/data`, two copies would fight over it;
- `readinessProbe` and `livenessProbe` hit `/healthz`;
- the image is pulled from a registry — if it is not published there, build and push your own.

Check without exposing it:

```bash
kubectl -n sigma2graylog port-forward svc/sigma2graylog 8080:80
```

---

## 5. Without a container (venv + systemd)

Requires Python 3.12.

```bash
sudo useradd -r -s /sbin/nologin s2g
sudo mkdir -p /opt/sigma2graylog /var/lib/sigma2graylog
sudo chown -R s2g:s2g /opt/sigma2graylog /var/lib/sigma2graylog

sudo -u s2g git clone https://github.com/ArsIS-02/sigma2graylog.git /opt/sigma2graylog
sudo -u s2g python3.12 -m venv /opt/sigma2graylog/.venv
sudo -u s2g /opt/sigma2graylog/.venv/bin/pip install -r /opt/sigma2graylog/requirements.txt

sudo install -m 600 /dev/null /etc/sigma2graylog.env
sudo $EDITOR /etc/sigma2graylog.env      # follow .env.example
```

Unit file: [`deploy/systemd/sigma2graylog.service`](deploy/systemd/sigma2graylog.service).

```bash
sudo cp /opt/sigma2graylog/deploy/systemd/sigma2graylog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigma2graylog
```

It listens on `127.0.0.1:8080` — publish it through a reverse proxy.

---

## 6. Reverse proxy and HTTPS

Examples: [`deploy/nginx/sigma2graylog.conf`](deploy/nginx/sigma2graylog.conf) and
[`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile).

```bash
sudo cp deploy/nginx/sigma2graylog.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

Keep in mind:

- `client_max_body_size 64m` — batch rule upload (up to 300 files);
- `proxy_read_timeout 300s` — history runs and batch conversion take a while;
- **HTTPS is recommended**: copying to the clipboard via `navigator.clipboard` only works in a secure
  context. Over `http://` there is an `execCommand` fallback, but HTTPS is more reliable;
- the app understands `X-Forwarded-*` (`uvicorn --proxy-headers` is already enabled in the image).

Caddy handles TLS automatically:

```bash
caddy run --config deploy/caddy/Caddyfile
```

---

## 7. Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GRAYLOG_URL` | yes | `http://127.0.0.1:9000` | Graylog API address |
| `GRAYLOG_PUBLIC_URL` | no | same as `GRAYLOG_URL` | address used in "open in search" links, must resolve from workstations |
| `GRAYLOG_USER` | yes* | — | Graylog service account |
| `GRAYLOG_PASSWORD` | yes* | — | its password |
| `GRAYLOG_TOKEN` | yes* | — | alternative to user/password |
| `APP_USER` | no | `sigma` | UI login (created on first start) |
| `APP_PASSWORD` | yes | — | password for `APP_USER` |
| `DATA_DIR` | no | `/data` | state directory |
| `FIELDS_TTL` | no | `600` | field list cache, seconds |
| `DEMO_MODE` | no | off | `1` — synthetic data instead of Graylog |

\* either `GRAYLOG_TOKEN` or the `GRAYLOG_USER` + `GRAYLOG_PASSWORD` pair is needed.

`APP_USER` / `APP_PASSWORD` are used **only on first start**. After that the password is changed in
the UI (menu under the avatar) and users live in `/data/users.json`.
The full annotated list is in [`.env.example`](.env.example).

If a setting exists both in the environment and in the UI, the UI one wins: it is stored in
`/data/settings.json`, encrypted.

---

## 8. Data and backup

All state is in `/data`:

| File | Contents |
|---|---|
| `users.json` | UI users (scrypt hashes) |
| `secret.key` | settings encryption key (Fernet) |
| `settings.json` | Graylog connection, passwords encrypted |
| `overrides.json` | remembered field mappings |
| `stream_overrides.json` | per-stream manual mapping |
| `sources/` | cache of downloaded rule sets |

Backup:

```bash
docker run --rm -v s2g-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/s2g-data-$(date +%F).tar.gz -C /data .
```

Restore:

```bash
docker run --rm -v s2g-data:/data -v "$PWD:/backup" alpine \
  tar xzf /backup/s2g-data-2026-10-29.tar.gz -C /data
```

`secret.key` is critical: without it the saved passwords in `settings.json` cannot be decrypted.

---

## 9. Offline install

On a machine with internet access:

```bash
docker build -t sigma2graylog:latest .
docker save sigma2graylog:latest | gzip > sigma2graylog.tar.gz
```

On the isolated host:

```bash
gunzip -c sigma2graylog.tar.gz | docker load
# or: podman load -i sigma2graylog.tar.gz
docker run -d --name sigma2graylog --env-file .env -p 8080:8080 -v s2g-data:/data sigma2graylog:latest
```

Rules work offline too: download the SigmaHQ set beforehand — it is cached in `/data/sources`
after the first load from the UI.

---

## 10. Post-install check

```bash
curl -s http://localhost:8080/healthz          # {"ok": true}
curl -s http://localhost:8080/api/status | head -c 300
```

`/api/status` returns `demo`, the Graylog version, field and stream counts — the quickest way to
confirm the Graylog connection really works.

Then: open the UI, sign in, **Settings** → "Test connection", and follow the
[guide](README.en.md#built-in-guide-1) step by step.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container restarts immediately, log shows `PermissionError: /data` | SELinux blocks the directory | `-v ...:/data:Z` or `--security-opt label=disable` |
| UI password "reset" after recreating the container | `:Z` changed the MCS categories, `users.json` became unreadable | recreate the volume with `label=disable`, see [3.4](#34-selinux-and-data-permissions) |
| `address already in use` | port 8080 is taken | `-p 8081:8080` |
| UI says Graylog is unreachable | wrong URL or network | `GRAYLOG_URL` must be reachable **from the container**, not only from the host; check with `podman exec` / `docker exec` + `curl` |
| "Open in Graylog" links do not work | `GRAYLOG_PUBLIC_URL` does not resolve from your workstation | set an address your browser can reach |
| Copy to clipboard does nothing | the page is served over `http://` | use HTTPS, or the `execCommand` fallback |
| Streams load slowly | the first analysis walks the indexes | warm the field cache, increase `FIELDS_TTL` |
| Empty "Guide" tab | JS was stripped during image build | check `docker logs` for a syntax error |

Logs:

```bash
docker logs -f sigma2graylog
podman logs -f sigma2graylog
journalctl --user -u sigma2graylog -f      # quadlet
journalctl -u sigma2graylog -f             # systemd without a container
```

---

## 12. Extra scenarios

**Two instances on one host** — production and demo:

```bash
docker run -d --name s2g-prod --env-file .env -p 8080:8080 -v s2g-data:/data sigma2graylog:latest
docker run -d --name s2g-demo -e DEMO_MODE=1 -p 8090:8080 sigma2graylog:latest
```

**Without exposing the port** — SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@server     # then open http://localhost:8080
```

**Inside an existing compose stack** — copy the `sigma2graylog` service into your file and attach it
to the same network as Graylog; then `GRAYLOG_URL` can use the service name, e.g. `http://graylog:9000`.

**Windows and macOS** — Docker Desktop, the commands from section 2 work unchanged.

**Publishing to a registry** (for Kubernetes and several hosts):

```bash
docker tag sigma2graylog:latest ghcr.io/<owner>/sigma2graylog:latest
docker push ghcr.io/<owner>/sigma2graylog:latest
```
