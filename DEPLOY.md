# Развёртывание

**English version: [DEPLOY.en.md](DEPLOY.en.md)**


Приложение — один контейнер: FastAPI + uvicorn на порту 8080, состояние в каталоге `/data`.
Ниже — варианты от «посмотреть за минуту» до продакшена с автозапуском.

## Что выбрать

| Ситуация | Вариант |
|---|---|
| Просто посмотреть, Graylog ещё нет | [Демо-режим](#1-демо-режим-без-graylog) |
| Один сервер, Docker | [`docker run`](#21-docker-run) или [Compose](#22-docker-compose) |
| Один сервер, РЕД ОС / Fedora / RHEL | [Podman + quadlet](#33-автозапуск-через-systemd-quadlet) |
| Уже есть кластер | [Kubernetes / k3s](#4-kubernetes--k3s) |
| Нельзя контейнеры | [venv + systemd](#5-без-контейнера-venv--systemd) |
| Нет доступа в интернет | [Офлайн-установка](#9-офлайн-установка) |

Минимальные требования: 1 vCPU, 256 МБ ОЗУ, 500 МБ диска, сетевой доступ к API Graylog (обычно порт 9000).

---

## 1. Демо-режим (без Graylog)

Синтетические данные: 5 стримов, 68 полей, 10 детектов. Вход не требуется — открывается сразу интерфейс.

```bash
docker build -t sigma2graylog:latest https://github.com/ArsIS-02/sigma2graylog.git

docker run -d --name sigma2graylog-demo -p 8080:8080 -e DEMO_MODE=1 sigma2graylog:latest
```

Открыть `http://localhost:8080`. Демо-режим удобно держать постоянно рядом с рабочим экземпляром — на другом порту:

```bash
docker run -d --name sigma2graylog-demo -p 8090:8080 -e DEMO_MODE=1 sigma2graylog:latest
```

Готовый файл: [`docker-compose.demo.yml`](docker-compose.demo.yml).

```bash
docker compose -f docker-compose.demo.yml up -d
```

---

## 2. Docker

### 2.1. `docker run`

```bash
git clone https://github.com/ArsIS-02/sigma2graylog.git
cd sigma2graylog
docker build -t sigma2graylog:latest .
```

Подготовьте окружение:

```bash
cp .env.example .env
$EDITOR .env          # GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASSWORD, APP_PASSWORD
```

Запуск:

```bash
docker run -d --name sigma2graylog \
  --env-file .env \
  -p 8080:8080 \
  -v s2g-data:/data \
  --restart unless-stopped \
  sigma2graylog:latest
```

Что важно в этой команде:

- `--env-file .env` — все параметры подключения без правки образа;
- `-v s2g-data:/data` — именованный том. Без него при пересоздании контейнера
  потеряются пользователи, настройки и сохранённые маппинги;
- `--restart unless-stopped` — подъём после перезагрузки хоста.

Проверка:

```bash
docker logs -f sigma2graylog      # в логе: Uvicorn running on http://0.0.0.0:8080
curl -s http://localhost:8080/healthz
```

### 2.2. Docker Compose

```bash
cp .env.example .env && $EDITOR .env
docker compose up -d --build
docker compose logs -f
```

Файл [`docker-compose.yml`](docker-compose.yml) уже содержит том, healthcheck и проброс порта
(порт меняется переменной `S2G_PORT`).

### 2.3. Обновление

```bash
git pull
docker compose build
docker compose up -d
```

Том `/data` не затрагивается: настройки, пользователи и пароли сохраняются.

---

## 3. Podman

Отличия от Docker: работает без демона и умеет rootless-режим. Основная тонкость — SELinux.

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

Суффикс `:Z` обязателен на SELinux-системах (РЕД ОС, Fedora, RHEL): без него контейнер
не получит доступ к каталогу и приложение упадёт на записи в `/data`.

### 3.2. `podman-compose`

```bash
podman-compose -f podman-compose.yaml up -d
podman-compose -f podman-compose.yaml logs -f
```

### 3.3. Автозапуск через systemd (quadlet)

Для Podman 4.4+ предпочтительный способ в продакшене: контейнером управляет systemd,
перезапуск и старт после загрузки хоста — на его стороне.

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/sigma2graylog.container ~/.config/containers/systemd/
cp .env.example ~/sigma2graylog.env && $EDITOR ~/sigma2graylog.env

systemctl --user daemon-reload
systemctl --user enable --now sigma2graylog
loginctl enable-linger $USER      # работа без активной сессии пользователя
```

Управление:

```bash
systemctl --user status sigma2graylog
journalctl --user -u sigma2graylog -f
systemctl --user restart sigma2graylog
```

В юните уже настроены `HealthCmd`, `AutoUpdate=registry` и том `s2g-data`.
Если у вас Podman старше 4.4 — используйте устаревший, но рабочий способ:

```bash
podman generate systemd --new --name sigma2graylog > ~/.config/systemd/user/sigma2graylog.service
systemctl --user daemon-reload && systemctl --user enable --now sigma2graylog
```

### 3.4. SELinux и права на `/data`

Два случая, которые чаще всего ломают установку:

**Bind-mount на хостовый каталог.** Нужен `:Z`:

```bash
mkdir -p /srv/sigma2graylog
podman run -d --name sigma2graylog -p 8080:8080 --env-file .env \
  -v /srv/sigma2graylog:/data:Z localhost/sigma2graylog:latest
```

**Каталог уже был размечен, и `:Z` меняет MCS-категории.** При каждом пересоздании
контейнера Podman выдаёт каталогу новые категории, старые файлы становятся нечитаемыми,
приложение не находит `users.json` и создаёт его заново — пароль «слетает» на тот, что
указан в переменных окружения. Если это происходит, отключите разметку для контейнера:

```bash
podman run -d --name sigma2graylog --security-opt label=disable \
  -p 8080:8080 --env-file .env \
  -v /srv/sigma2graylog:/data localhost/sigma2graylog:latest
```

---

## 4. Kubernetes / k3s

Готовый манифест: [`deploy/k8s/sigma2graylog.yaml`](deploy/k8s/sigma2graylog.yaml) —
Namespace, Secret, PVC на 1 ГиБ, Deployment, Service и Ingress.

```bash
$EDITOR deploy/k8s/sigma2graylog.yaml    # образ, домен, пароли в Secret
kubectl apply -f deploy/k8s/sigma2graylog.yaml
kubectl -n sigma2graylog get pods -w
```

Особенности:

- реплика всегда одна (`strategy: Recreate`): состояние живёт в `/data`, две копии
  разделят файлы и будут перетирать настройки;
- `readinessProbe` и `livenessProbe` смотрят на `/healthz`;
- образ тянется из реестра — если его там нет, соберите и запушьте в свой.

Проверка без публикации наружу:

```bash
kubectl -n sigma2graylog port-forward svc/sigma2graylog 8080:80
```

---

## 5. Без контейнера (venv + systemd)

Нужен Python 3.12.

```bash
sudo useradd -r -s /sbin/nologin s2g
sudo mkdir -p /opt/sigma2graylog /var/lib/sigma2graylog
sudo chown -R s2g:s2g /opt/sigma2graylog /var/lib/sigma2graylog

sudo -u s2g git clone https://github.com/ArsIS-02/sigma2graylog.git /opt/sigma2graylog
sudo -u s2g python3.12 -m venv /opt/sigma2graylog/.venv
sudo -u s2g /opt/sigma2graylog/.venv/bin/pip install -r /opt/sigma2graylog/requirements.txt

sudo install -m 600 /dev/null /etc/sigma2graylog.env
sudo $EDITOR /etc/sigma2graylog.env      # по образцу .env.example
```

Юнит: [`deploy/systemd/sigma2graylog.service`](deploy/systemd/sigma2graylog.service).

```bash
sudo cp /opt/sigma2graylog/deploy/systemd/sigma2graylog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigma2graylog
```

Слушает `127.0.0.1:8080` — снаружи публикуйте через реверс-прокси.

---

## 6. Реверс-прокси и HTTPS

Примеры: [`deploy/nginx/sigma2graylog.conf`](deploy/nginx/sigma2graylog.conf) и
[`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile).

```bash
sudo cp deploy/nginx/sigma2graylog.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

Что учесть:

- `client_max_body_size 64m` — пакетная загрузка правил (до 300 файлов);
- `proxy_read_timeout 300s` — прогон по истории и конвертация пачки идут долго;
- **HTTPS желателен**: копирование в буфер обмена через `navigator.clipboard` работает
  только в защищённом контексте. На `http://` остаётся запасной путь через `execCommand`,
  но в HTTPS он надёжнее;
- приложение понимает `X-Forwarded-*` (`uvicorn --proxy-headers` уже включён в образе).

Caddy делает TLS автоматически:

```bash
caddy run --config deploy/caddy/Caddyfile
```

---

## 7. Переменные окружения

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `GRAYLOG_URL` | да | `http://127.0.0.1:9000` | адрес API Graylog |
| `GRAYLOG_PUBLIC_URL` | нет | как `GRAYLOG_URL` | адрес для ссылок «в поиск», должен резолвиться с рабочих машин |
| `GRAYLOG_USER` | да* | — | сервисная учётная запись Graylog |
| `GRAYLOG_PASSWORD` | да* | — | её пароль |
| `GRAYLOG_TOKEN` | да* | — | альтернатива паре логин/пароль |
| `APP_USER` | нет | `sigma` | логин в интерфейсе (создаётся при первом старте) |
| `APP_PASSWORD` | да | — | пароль для `APP_USER` |
| `DATA_DIR` | нет | `/data` | каталог состояния |
| `FIELDS_TTL` | нет | `600` | кэш списка полей, секунды |
| `DEMO_MODE` | нет | выкл | `1` — синтетические данные вместо Graylog |

\* нужен либо `GRAYLOG_TOKEN`, либо пара `GRAYLOG_USER` + `GRAYLOG_PASSWORD`.

Переменные `APP_USER` / `APP_PASSWORD` действуют **только при первом старте**. Дальше пароль
меняется в интерфейсе (меню под аватаром), пользователи живут в `/data/users.json`.
Полный перечень с комментариями — [`.env.example`](.env.example).

Если настройки заданы и в переменных, и в интерфейсе, побеждают сохранённые в интерфейсе:
они хранятся в `/data/settings.json` в зашифрованном виде.

---

## 8. Данные и бэкап

Всё состояние — в `/data`:

| Файл | Что внутри |
|---|---|
| `users.json` | пользователи интерфейса (scrypt-хеши) |
| `secret.key` | ключ шифрования настроек (Fernet) |
| `settings.json` | подключение к Graylog, поля паролей зашифрованы |
| `overrides.json` | запомненные сопоставления полей |
| `stream_overrides.json` | ручной маппинг по стримам |
| `sources/` | кэш скачанных наборов правил |

Бэкап:

```bash
docker run --rm -v s2g-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/s2g-data-$(date +%F).tar.gz -C /data .
```

Восстановление:

```bash
docker run --rm -v s2g-data:/data -v "$PWD:/backup" alpine \
  tar xzf /backup/s2g-data-2026-10-29.tar.gz -C /data
```

Файл `secret.key` критичен: без него сохранённые пароли в `settings.json` не расшифруются.

---

## 9. Офлайн-установка

На машине с интернетом:

```bash
docker build -t sigma2graylog:latest .
docker save sigma2graylog:latest | gzip > sigma2graylog.tar.gz
```

На изолированном хосте:

```bash
gunzip -c sigma2graylog.tar.gz | docker load
# либо: podman load -i sigma2graylog.tar.gz
docker run -d --name sigma2graylog --env-file .env -p 8080:8080 -v s2g-data:/data sigma2graylog:latest
```

Для установки без интернета пригодятся и правила: скачайте набор SigmaHQ заранее —
он закэшируется в `/data/sources` после первой загрузки в интерфейсе.

---

## 10. Проверка после установки

```bash
curl -s http://localhost:8080/healthz          # {"ok": true}
curl -s http://localhost:8080/api/status | head -c 300
```

`/api/status` возвращает `demo`, версию Graylog, число полей и стримов — быстрый способ
убедиться, что подключение к Graylog действительно работает.

Дальше: открыть интерфейс, войти, вкладка **«Настройки»** → «Проверить соединение», и
пройти [руководство](README.md#встроенное-руководство) по шагам.

---

## 11. Устранение неполадок

| Симптом | Причина | Решение |
|---|---|---|
| Контейнер сразу перезапускается, в логах `PermissionError: /data` | SELinux не даёт доступ к каталогу | `-v ...:/data:Z` или `--security-opt label=disable` |
| Пароль в интерфейсе «сбросился» после пересоздания контейнера | `:Z` сменил MCS-категории, `users.json` стал нечитаемым | пересоздать том с `label=disable`, см. [3.4](#34-selinux-и-права-на-data) |
| `address already in use` | порт 8080 занят | `-p 8081:8080` |
| В интерфейсе «Graylog недоступен» | неверный URL или сеть | `GRAYLOG_URL` должен быть доступен **из контейнера**, не только с хоста; проверьте `podman exec` / `docker exec` + `curl` |
| Ссылка «открыть в Graylog» не работает | `GRAYLOG_PUBLIC_URL` не резолвится с рабочей машины | задать адрес, доступный из браузера |
| Копирование в буфер не срабатывает | страница открыта по `http://` | зайти по HTTPS или использовать кнопку с запасным путём `execCommand` |
| Долго грузятся стримы | первый анализ обходит индексы | прогрев кэша полей, `FIELDS_TTL` побольше |
| Пустая вкладка «Руководство» | обрезался JS при сборке образа | проверить `docker logs` на ошибку синтаксиса |

Логи:

```bash
docker logs -f sigma2graylog
podman logs -f sigma2graylog
journalctl --user -u sigma2graylog -f      # quadlet
journalctl -u sigma2graylog -f             # systemd без контейнера
```

---

## 12. Дополнительные сценарии

**Два экземпляра на одном хосте** — рабочий и демонстрационный:

```bash
docker run -d --name s2g-prod --env-file .env -p 8080:8080 -v s2g-data:/data sigma2graylog:latest
docker run -d --name s2g-demo -e DEMO_MODE=1 -p 8090:8080 sigma2graylog:latest
```

**Без публикации порта наружу** — доступ через SSH-туннель:

```bash
ssh -L 8080:127.0.0.1:8080 user@server     # затем http://localhost:8080
```

**В существующем compose-стеке** — скопируйте сервис `sigma2graylog` в свой файл и
подключите к той же сети, что и Graylog; тогда `GRAYLOG_URL` можно указать по имени
сервиса, например `http://graylog:9000`.

**Windows и macOS** — Docker Desktop, команды из раздела 2 без изменений.

**Публикация в реестр** (для Kubernetes и нескольких хостов):

```bash
docker tag sigma2graylog:latest ghcr.io/<owner>/sigma2graylog:latest
docker push ghcr.io/<owner>/sigma2graylog:latest
```
