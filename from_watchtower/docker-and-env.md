# Docker and environment

Current Watchtower deployment reference: `/opt/docker/docker-compose.yml`, `/opt/docker/.env.example`.

Target: independent Compose stack for phishing-only workloads.

## Current Watchtower env (phishing-related)

From `docker-compose.yml` (web service excerpts):

| Variable | Typical value | Purpose |
|----------|---------------|---------|
| `PHISHING_GMAIL_SERVICE_ACCOUNT_FILE` | `/opt/secrets/phishing-gmail.json` | Domain-wide delegation JSON path (host + container mount) |
| `PHISHING_GMAIL_GROUP_INGEST_MAILBOX` | `watchtowerapi@washk12.org` | Impersonation target for group forwards |
| `PHISHING_GMAIL_GROUP_FORWARD_ADDRESS` | `phishing@washk12.org` | Documented forward address (search in scripts) |
| `AI_SERVICE_URL` | `http://ai_broker:5000` | Reporter AI + Gemini proxy |
| `IPQUALITYSCORE_API_KEY` | secret | Intel scans |
| `VIRUSTOTAL_API_KEY` | secret | URL VT |
| `APIFLASH_API_KEY` | secret | Screenshots |

Django reads additional `PHISHING_*` tuning in `watchtower/settings.py` (cluster caps, delegation scopes, original search window). Defaults are safe; override via env if exposed.

Gmail SA file must be **mounted read-only** into web (and worker if split):

```yaml
volumes:
  - ./secrets/phishing-gmail.json:/opt/secrets/phishing-gmail.json:ro
environment:
  PHISHING_GMAIL_SERVICE_ACCOUNT_FILE: /opt/secrets/phishing-gmail.json
```

Workspace Admin: authorize SA client id with scopes used in `phishing/gmail_service.py` (includes Gmail modify for fetch).

## Proposed standalone Compose

```yaml
services:
  phishing_db:
    image: postgres:16
    environment:
      POSTGRES_DB: phishing
      POSTGRES_USER: phishing
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - phishing_pgdata:/var/lib/postgresql/data

  phishing_web:
    build: .
    command: gunicorn phishing_service.wsgi:application
    env_file:
      - .env
    environment:
      DATABASE_URL: postgres://phishing:${POSTGRES_PASSWORD}@phishing_db:5432/phishing
      PHISHING_GMAIL_SERVICE_ACCOUNT_FILE: /opt/secrets/phishing-gmail.json
      AI_SERVICE_URL: http://phishing_ai:5000
    volumes:
      - ./secrets/phishing-gmail.json:/opt/secrets/phishing-gmail.json:ro
    ports:
      - "8080:8000"
    depends_on:
      - phishing_db
      - phishing_ai

  phishing_worker:  # optional but recommended
    build: .
    command: celery -A phishing_service worker -l info  # or rq worker
    env_file: .env
    volumes:
      - ./secrets/phishing-gmail.json:/opt/secrets/phishing-gmail.json:ro
    depends_on:
      - phishing_db

  phishing_ai:  # optional — copy ai_broker/
    build: ./ai_broker
    env_file:
      - ./ai_broker/ai_connections.env
```

Replace daemon-thread RFC822 resolve with **worker queue** for production reliability.

## New service `.env` template

```bash
# Database
POSTGRES_PASSWORD=
DATABASE_URL=postgres://phishing:@phishing_db:5432/phishing

# Django
SECRET_KEY=
ALLOWED_HOSTS=phishing.washk12.org
DEBUG=0

# Gmail API
PHISHING_GMAIL_SERVICE_ACCOUNT_FILE=/opt/secrets/phishing-gmail.json
PHISHING_GMAIL_GROUP_INGEST_MAILBOX=watchtowerapi@washk12.org
PHISHING_GMAIL_GROUP_FORWARD_ADDRESS=phishing@washk12.org

# Threat intel (moved from Watchtower)
IPQUALITYSCORE_API_KEY=
VIRUSTOTAL_API_KEY=
APIFLASH_API_KEY=

# AI broker
AI_SERVICE_URL=http://phishing_ai:5000
AI_SERVICE_GEMINI_PATH=/api/gemini
# Or inline Gemini:
# GEMINI_API_KEY=
```

Keep **`ai_broker/ai_connections.env`** out of git; use `.example` only.

## Management commands (ops)

Run inside `phishing_web` container:

| Command | Purpose |
|---------|---------|
| `resolve_phishing_gmail_rfc822` | Backfill RFC822 + body for pending gmail-report rows |
| `backfill_phishing_parsed_email` | Re-parse stored bodies |

After migration, same commands operate on `PhishingReport` once adapted.

## Cutover checklist

### Infrastructure

- [ ] Postgres provisioned; migrations applied
- [ ] SA JSON mounted; delegation tested against ingest + sample staff mailbox
- [ ] TLS hostname for new service
- [ ] Secrets: IPQS, VT, ApiFlash, Gemini, Django `SECRET_KEY`

### Auth

- [ ] API client token issued with `phishing_gmail_report_api` equivalent
- [ ] Staff accounts or SSO for `/phishing/`

### Clients

- [ ] Update Apps Script URLs + `WEBHOOK_SECRET`
- [ ] Smoke: POST report, GET campaigns, POST feedback
- [ ] Group script hourly run verified

### Data (optional parallel)

- [ ] Historical import with `legacy_communication_id`
- [ ] Dual-write period OR read-only mirror validation

### Watchtower decommission

- [ ] Remove URL includes from `watchtower/urls.py`
- [ ] Stop mounting phishing-only secrets on Watchtower web if unused
- [ ] Archive or disable legacy email webhook phishing branch

## Health checks

- GET `/api/phishing/reported-campaigns/?hours=1` with valid token → 200
- Internal: Gmail SA configured flag true (`gmail_delegation_configured()`)
- DB connectivity via Django migrate / health endpoint

## Logging

Watchtower today: standard Django logging for `phishing.gmail_report_api`, resolve errors in `gmail_rfc822_resolve`.

Standalone: structured logs for fetch failures (`rfc822_fetch_status` in metadata) aid group-ingest debugging.
