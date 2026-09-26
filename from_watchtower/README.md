# Phishing service extraction — documentation index

This folder documents the **Watchtower-embedded phishing system** as it exists in `/opt/docker` today, so another team or agent can build a **standalone Django + Postgres Docker service** with its own database and `.env` (including threat-intel and Gemini keys).

## What this system does

Washington County School District (WCSD) staff report suspicious email through:

1. **Gmail add-on** — users click Report; the add-on POSTs a Gmail **internal message id** to Watchtower.
2. **Phishing group mailbox** — users forward to `phishing@…`; an Apps Script in the **ingest mailbox** (`watchtowerapi@…`) POSTs the same API with group-ingest metadata.
3. **Analyst dashboard** — `/phishing/` lists clustered campaigns, threat meter, and per-report review (parse, URLs, emails, AI guidance, manual verdict).
4. **District warnings in Gmail** — the add-on GETs recent **reported campaigns**, matches open mail (RFC822 ids, forwards, subject/origin), applies labels, and shows analyst verdict when available.

Automated steps after report: Gmail API fetch (domain-wide delegation) → RFC822 Message-ID + body → parse → heuristic risk → optional IPQS/VT scans and Gemini/internal reporter AI → subject/campaign clustering.

## Primary users

| Actor | Interface |
|-------|-----------|
| Staff reporters | Gmail add-on, forward to phishing group |
| Security analysts | `/phishing/`, incident detail, verdict, bad-actor tools |
| All staff (passive) | Gmail labels + add-on sidebar when mail matches a campaign |
| Automation | Apps Script (hourly group ingest), background RFC822 resolve threads |

## Code map (Watchtower monolith)

| Area | Path |
|------|------|
| Django app | `phishing/` (~58 Python modules) |
| Public APIs | `phishing/gmail_report_api.py` (mounted in `watchtower/urls.py`) |
| UI routes | `phishing/urls.py`, templates under `templates/watchtower/` |
| Gmail scripts (deploy separately) | `scripts/temp_phishing_reporter_ui.gs`, `scripts/watchtowerapi@wahsk12.org_script` |
| Threat intel | `phishing/bad_actor_views.py` → `security/` (IPQS, VT, BadActorProfile) |
| AI | `AI_SERVICE_URL` → `ai_broker/` (Gemini + internal chat) |
| Shared row storage | `communications.Communication` (webhook rows) + `phishing.PhishingSubmission` (1:1 analysis) |

## Documentation files

| Document | Contents |
|----------|----------|
| [architecture.md](architecture.md) | Components, data flow, deployment view |
| [ingestion-and-message-ids.md](ingestion-and-message-ids.md) | Gmail id vs RFC822 id, duplicates, forwards, resolve pipeline |
| [google-apps-script.md](google-apps-script.md) | Add-on + group ingest, auth, matching, labels |
| [http-api.md](http-api.md) | REST contracts for add-on and staff JSON endpoints |
| [dashboard-and-analyst-workflow.md](dashboard-and-analyst-workflow.md) | `/phishing/` logic, clustering, verdicts, performance |
| [data-model.md](data-model.md) | Current schema and recommended standalone schema |
| [intel-and-ai.md](intel-and-ai.md) | Bad Actor, IPQS/VT/ApiFlash, reporter AI, env keys |
| [watchtower-coupling-inventory.md](watchtower-coupling-inventory.md) | Cross-app imports to copy or replace |
| [docker-and-env.md](docker-and-env.md) | Containers, secrets, cutover checklist |
| [framework-alternatives.md](framework-alternatives.md) | Django vs alternatives |

## Phased migration (recommended)

### Phase A — Stand up new service (parallel)

- New repo or compose stack: `phishing_web`, `phishing_db` (Postgres), optional worker for RFC822 queue, optional `phishing_ai` (broker copy).
- Port `phishing/` + required `security/` subset + slim auth (API client tokens + staff login).
- Replace `Communication` dependency with first-class `PhishingReport` model (see [data-model.md](data-model.md)).
- Deploy with **new hostnames**; do not cut traffic yet.

### Phase B — Traffic switch

- Point Apps Script `WEBHOOK_URL`, `CAMPAIGNS_URL`, `FEEDBACK_URL` to new host.
- Migrate historical rows (or run dual-read with `legacy_communication_id`).
- Verify: duplicate reports, group ingest mailbox fetch, add-on campaign match + labels.

### Phase C — Decommission in Watchtower

- Remove or proxy `path('phishing/', …)` and `api/phishing/*` in `watchtower/urls.py`.
- Drop homepage phishing section if unused (`watchtower/dashboard_sections.py`).

## File manifest for downstream implementer

**Copy/adapt (core domain):**

- `phishing/*.py` (except tests initially)
- `phishing/migrations/` as reference only — generate fresh migrations on new models
- Templates: `templates/watchtower/phishing_*`, `templates/watchtower/partials/phishing_*`, CSS under `watchtower/static/css/phishing_*`

**Copy/adapt (intel — per product decision):**

- `security/models.py` (BadActor* subset), `security/ipqs_*`, `security/virustotal_*`, `security/bad_actor_*`
- `ai_broker/` or embed Gemini client in new service

**Rewrite (do not copy blindly):**

- Auth: `watchtower/feature_access.py`, `AuthorizedMobileDeviceModel`, `resolve_api_client_auth`
- Any `UserCommunicationModel` / `Communication` FK — map to `PhishingReport`
- `watchtower/views.py` webhook ingest hook (~14592) if retiring legacy email webhook path
- Dashboard shell: `dashboard_base.html`, sidebar — simplify to phishing-only layout

**Keep external (no port):**

- Google Apps Script projects (update URLs only)
- Workspace Admin: domain-wide delegation for Gmail service account

## Out of scope for this documentation set

- Automated data migration SQL
- Production URL changes in Google Workspace
- Splitting git history

When implementing, treat this bundle plus the cited source files as the specification of behavior to preserve.
