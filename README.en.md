<p align="center">
  <img src="docs/logo.svg" width="104" alt="sigma2graylog">
</p>

<h1 align="center">sigma2graylog</h1>

[![build and tests](https://github.com/ArsIS-02/sigma2graylog/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsIS-02/sigma2graylog/actions/workflows/ci.yml)
[![license: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![python 3.12](https://img.shields.io/badge/python-3.12-3776AB.svg)](https://www.python.org/)
[![Graylog 7.x](https://img.shields.io/badge/Graylog-7.x-ff3633.svg)](https://graylog.org/)

**Convert Sigma rules into Graylog detections — matched against the fields that actually exist in your indices.**

Sigma rules are written in terms of Windows event fields (`Image`, `CommandLine`, `EventID`),
while Graylog stores them as `winlogbeat_winlog_event_data_Image`, `exe`, `proctitle`, `name` and so on.
Pasting a Sigma query into Graylog usually produces a query that silently matches nothing.
This tool closes that gap: it parses the rule with [pySigma](https://github.com/SigmaHQ/pySigma),
picks the stream belonging to the rule's product, maps every field onto the real field list of that
stream, rewrites the query into syntax Graylog accepts, and shows how noisy the rule is on your own
historical data — before you create a detection.

![Converter](docs/screenshots/01-converter.png)

## Features

| | |
|---|---|
| **Conversion** | Sigma YAML to Graylog Lucene query, single rule or batches |
| **Field mapping** | per-stream field lists, product routing, semantic dictionary, manual overrides |
| **Stream analysis** | which Sigma fields a stream covers, which are missing, and what to do about it |
| **History run** | per-day hit counts for the last 30 days, "noisy / quiet" verdict, sample events |
| **Duplicate check** | compares a new query with existing event definitions (query tokens + title) |
| **Detections tab** | browse, search, open and delete existing Graylog event definitions |
| **Batch mode** | table with filters, bulk creation with a dry-run preview and per-item report |
| **Rule library** | public Sigma sets (SigmaHQ, ThreatHunting Keywords, ...): load a whole set or one product, per-product breakdown |
| **MITRE ATT&CK** | the rule's `attack.*` tags are written to the detection's events as `mitre_tactic`, `mitre_technique`, `mitre_techniques` (ATT&CK v20 reference, obsolete IDs are replaced) |
| **ATT&CK coverage** | a tab with the ATT&CK matrix: which techniques your detections cover, definitions per technique on click, a layer for ATT&CK Navigator |
| **Extractor generator** | emits a Graylog pipeline rule for a field missing in your stream |
| **Settings UI** | Graylog URL, token or password, cache TTL, defaults — secrets encrypted at rest |
| **Built-in guide** | a "Guide" tab: seven annotated steps with animated pointers |
| **Two languages** | Russian and English UI, switcher in the header, `?lang=en` links |

## Built-in guide

The app has a **Guide** tab — the path from connecting to Graylog to a working detection in seven
steps. Each step is a short text plus a screenshot where the relevant elements are outlined,
numbered and marked with pulsing pointers. The guide is fully translated, and each language has its
own screenshots taken from that language's UI.

![Guide](docs/screenshots/en/06-guide.png)

## Languages

The UI is bilingual: Russian and English. The **RU / EN** switcher is in the top right corner; the
choice is remembered in the browser, and a link can force it with `?lang=en`.

Translated: tabs, buttons, hints, conversion warnings (built on the server and returned in the
requested language), the built-in guide with its illustrations, and demo-mode sample data.

![Streams](docs/screenshots/en/02-streams.png)

### Correlations and thresholds

Sigma correlation rules (`event_count`, `value_count`) become a Graylog event definition with grouping and a threshold, e.g. "10 failed logons from one address within 5 minutes". See [docs/CORRELATION.md](docs/CORRELATION.md).

### MITRE ATT&CK coverage

The **ATT&CK** tab shows a matrix of tactics and techniques covered by Graylog alerts; the layer can be exported for ATT&CK Navigator. See [docs/ATTACK.md](docs/ATTACK.md).

![ATT&CK coverage](docs/screenshots/en/08-attack.png)

## Quick start (demo, no Graylog needed)

```bash
git clone https://github.com/ArsIS-02/sigma2graylog.git
cd sigma2graylog
docker compose -f docker-compose.demo.yml up --build
# or: podman-compose -f docker-compose.demo.yml up --build
```

Open http://localhost:8080 — the app runs on synthetic data, no login required.

## Quick start (real Graylog)

```bash
cp .env.example .env
# edit GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASSWORD, APP_PASSWORD
podman build -t sigma2graylog .
podman run -d --name sigma2graylog --restart unless-stopped \
  --security-opt label=disable \
  -p 8080:8080 --env-file .env -v /srv/sigma2graylog:/data sigma2graylog
```

Open http://localhost:8080, log in with `APP_USER` / `APP_PASSWORD`, then fill in the connection
details under Settings — the UI validates them with a live request to `/api/system`.

> On SELinux systems run with `--security-opt label=disable` and mount the data directory without
> `:Z`. With `:Z` podman assigns new MCS categories on every container re-creation, previously
> written files become unreadable, and the app re-creates `users.json` on start, silently resetting
> the password.

## Deployment

Full instructions in **English**: **[DEPLOY.en.md](DEPLOY.en.md)** — Russian: [DEPLOY.md](DEPLOY.md).

| Option | When it fits |
|---|---|
| `docker run` / `podman run` | take a look, single server |
| Docker Compose / podman-compose | several services side by side |
| Podman + systemd (quadlet) | production on RHEL / Fedora / RedOS |
| Kubernetes / k3s | you already run a cluster |
| venv + systemd | containers are not allowed |
| offline (`docker save` / `load`) | no internet access |

Ready-made files: [`docker-compose.yml`](docker-compose.yml),
[`podman-compose.yaml`](podman-compose.yaml), [`deploy/`](deploy) — quadlet unit, systemd service,
nginx and Caddy configs, a Kubernetes manifest.

## Configuration

| Variable | Purpose |
|---|---|
| `GRAYLOG_URL` | Graylog base URL, e.g. `http://graylog.example.com:9000` |
| `GRAYLOG_PUBLIC_URL` | URL used in generated links (must resolve from your workstation) |
| `GRAYLOG_USER` / `GRAYLOG_PASSWORD` | service account |
| `GRAYLOG_TOKEN` | alternative to user/password |
| `APP_USER` / `APP_PASSWORD` | UI credentials, used **only** to create the first user |
| `FIELDS_TTL` | field-list cache, seconds (default 600) |
| `DEMO_MODE` | `1` — synthetic data, no external Graylog |
| `ALLOW_PRIVATE_URLS` | `1` — allow loading "by link" from internal addresses (blocked by default) |

Values from the Settings tab override environment variables; they are stored in
`/data/settings.json` with `0600`, secrets encrypted (Fernet, key derived from `/data/secret.key`).

## How the mapping works

1. **Every stream gets a product** — inferred from the fields its events actually contain:
   `winlogbeat_*` -> windows, `audit_type` / `proctitle` -> linux, `macos_*` -> macos.
   Based on a sample of recent events, cached for 10 minutes.
2. **The rule's product selects the stream**, and the mapping universe becomes that stream's real
   fields instead of a global list. A `product: linux` rule can never be mapped onto `winlogbeat_*`.
3. **Semantic dictionary** covers the usual suspects: in auditd `CommandLine` is `proctitle`,
   `Image` is `exe`, `TargetFilename` is `name`; in Windows `Image` is `win_image` or
   `winlogbeat_winlog_event_data_Image`, whichever is more common in the sample.
4. **Confidence scoring** ranks candidates; anything below 70 is reported as "field not found" with
   suggestions instead of being silently substituted.

## Graylog quirks this tool works around

Verified against Graylog 7.2.1:

- `field:*value*` — **parse error** (leading wildcard without quotes);
- `field:"*value*"` — parses, but matches nothing;
- `field:/.*value.*/` — works; this is what `contains` / `endswith` compile to;
- regex in Graylog is **case-sensitive**, Sigma is not — enabled by default, letters are expanded
  into character classes (`[Pp]ower[Ss]hell`);
- inside a value, Sigma's `*` means "any characters" and `?` means "one character": in regex they
  become `.*` and `.`, while `/`, `"`, `&`, `#`, `~`, `<`, `>` and other Lucene-regex specials are
  escaped. Quotes and escapes (`\"`, `\ `) are parsed character by character, so values like
  `say "hi" there` do not break the query and a `*` inside a quoted phrase is left alone;
- `POST /api/events/definitions` needs the body wrapped in `{"entity": {...}}` with an empty
  `series` array;
- `DELETE` requires the `X-Requested-By` header.

## API

| Method | Path | |
|---|---|---|
| POST | `/api/convert` | `{sigma, overrides?, probe?, stream_id?}` -> queries, mapping, warnings |
| POST | `/api/history` | `{query, days, stream_id?}` -> per-day buckets, verdict, samples |
| POST | `/api/event-definition` | create one detection (requires `confirm: true`) |
| POST | `/api/event-definitions/bulk` | batch create with dry-run and duplicate skipping |
| GET | `/api/detections` | existing definitions, filters `all`, `never`, `matched` |
| GET | `/api/streams?profiles=true` | streams with detected product and field count |
| GET | `/api/streams/{id}/analysis` | Sigma coverage for a stream |
| POST | `/api/streams/{id}/overrides` | persist manual mapping for a stream |
| POST | `/api/sources/{id}/fetch` | download a public rule set, filter, return rules |
| GET/PUT | `/api/settings` | connection settings (secrets never returned) |

## Limitations

- Loading rules "by link" is protected against SSRF: localhost, private networks, link-local
  (cloud metadata) and IPv6 loopback/ULA are blocked, checked again on every redirect, and the
  download size is capped while streaming. Set `ALLOW_PRIVATE_URLS=1` for your own internal source.
- Regex is case-insensitive only through character classes, which makes long queries ~4x longer;
  expansion is skipped above 48 characters.
- A stream's field list comes from a sample of 100 events, so rare fields may be missed.
- Detections are created with `alert: false` and without notifications — wire those in Graylog.
- Field extraction is not performed: if a value exists only inside `message`, generate an extractor
  and apply it as a pipeline rule first.

## License

GPL-3.0 — see [LICENSE](LICENSE). Third-party components are listed in [THIRD-PARTY.md](THIRD-PARTY.md);
pySigma and pySigma-backend-elasticsearch are LGPL and are installed as dependencies, not vendored.

Russian documentation: [README.md](README.md).
