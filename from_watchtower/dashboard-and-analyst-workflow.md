# Dashboard and analyst workflow

Staff-facing phishing UX lives at **`/phishing/`** (included from `watchtower/urls.py`). Access gate: `has_phishing_mail_access` (`watchtower/feature_access.py`).

## Dashboard (`/phishing/`)

### View stack

| Layer | Module |
|-------|--------|
| View | `phishing/views.py` `phishing_dashboard` |
| Context | `phishing/dashboard.py` `build_phishing_dashboard_context` |
| Cards | `phishing/incident_card_groups.py` `build_phishing_incident_cards` |
| Latest incident header | `phishing/incidents.py` `find_latest_phishing_incident_summary` |
| Filters | `phishing/list_filters.py` |

### Query base

Parent webhook communications with phishing origin, no parent thread:

- `phishing_parent_submissions_queryset()` — wraps `inbound_webhook_mail_queryset` + webhook_origin icontains `phishing`.

Default list window: **`PHISHING_LIST_DEFAULT_DAYS`** (3). Page size **`PHISHING_LIST_PAGE_SIZE`** (50).

### Clustering

1. Load up to **`PHISHING_MAIL_CLUSTER_SOURCE_CAP`** (4000) recent parent rows.
2. `build_phishing_mail_cluster_list` groups by subject similarity (`PHISHING_SUBJECT_CLUSTER_MIN_RATIO` 0.9) within **`PHISHING_SUBJECT_GROUP_MAX_SPAN_HOURS`** (24h).
3. Cards merge clusters sharing RFC822 keys or origin+subject (`incident_card_groups.py`).

Each card exposes:

- `communication_id` (representative row)
- `member_communication_ids` (cluster peers)
- `report_count`, threat score/level
- `analyst_verdict`, `analyst_confidence`, `analyst_notes`, `analyst_verdict_at`
- Single **See Report** link to representative id (not per-row in table)

### Incident vs notify

`phishing/incidents.py`:

- **`is_phishing_incident`**: elevated auto score OR analyst verdict in `{phishing, malware}` unless verdict overrides to benign.
- **`pick_campaign_analyst_review`**: chooses display verdict/confidence for cards and API.
- Analyst **`legitimate`** verdict suppresses incident treatment even when score high.

Threshold: **`PHISHING_INCIDENT_ELEVATED_SCORE`** (50).

### Latest incident panel (performance)

`find_latest_phishing_incident_summary`:

- Scans at most **`PHISHING_LATEST_INCIDENT_SCAN_MAX`** (100) recent rows before clustering.
- Result cached **`phishing:dashboard:latest_incident_summary`** for 60 seconds.

Optional profiling: query param **`?phishing_profile=1`** (staff) adds timing logs and `Server-Timing` header from `views.py`.

### Known performance characteristics

- Full 30-day views still cluster large row sets before pagination — dominant cost is subject clustering O(n²) comparisons in worst case.
- Mitigations already in code: source cap, latest-incident cap + cache, reuse cluster groups for card building.
- Standalone service: consider precomputed campaign table updated on ingest, or background clustering job.

## Incident detail (`/phishing/incidents/<communication_id>/`)

### Data loading

- Row: `UserCommunicationModel` webhook with phishing origin.
- Analysis: `PhishingSubmission` 1:1; `effective_parsed_email` follows `cluster_canonical` peer.
- Mail assembly: `phishing/mail_assembly.py` — URLs, emails, thread items via `watchtower.views._build_webhook_mail_thread_items`.
- Threat display: `phishing/threat_assessment.py` (heuristic + optional Gemini/internal assessments).

### Analyst actions

| Action | Endpoint | Persistence |
|--------|----------|-------------|
| Set verdict | POST `…/verdict/` | `PhishingSubmission.analyst_*` fields |
| Bad actor match/associate/create | POST `…/bad-actor/*` | `security` models + links |
| Scan URLs | POST `…/review-urls/analyze/` | Scan log on BadActor profiles |
| Scan emails | POST `…/review-emails/analyze/` | IPQS validation cache |
| Reporter AI | POST `…/reporter-ai-guidance/run/` | `reporter_ai_guidance_json`, timestamps |
| URL screenshot | GET `…/url-screenshot/` | ApiFlash fetch + cache |

Verdict save busts dashboard latest-incident cache.

### Templates / static

- `templates/watchtower/phishing_dashboard.html`
- `templates/watchtower/phishing_incident_detail.html`
- `templates/watchtower/partials/phishing_incident_cards.html`
- CSS: `watchtower/static/css/phishing_*.css` (version query strings in templates)

### Home dashboard section (optional)

`templates/home/sections/phishing_incidents_section.html` + `watchtower/dashboard_sections.py` — embeds subset of phishing incidents on main home; full tool remains `/phishing/`.

## Reporter-facing analysis (API)

After report, add-on may receive **`summarize_phishing_report_analysis`** (`phishing/report_analysis_summary.py`):

- Picks best submission for gmail message id (peer cluster lookup via artifacts).
- Merges analyst verdict into display strings.
- Used on duplicate POST responses.

## Cluster automation (legacy path)

`phishing/cluster_auto_pipeline.py` runs auto URL/email scans + Gemini when cluster size ≥ 2 on **legacy email webhook** ingest. **Not** triggered from gmail-report API today — gap to close in standalone service if desired.

## Access control summary

| Surface | Check |
|---------|-------|
| `/phishing/*` | `login_required` + `has_phishing_mail_access` |
| `/api/phishing/*` | API client + `phishing_gmail_report_api` rule |

Standalone: replace Watchtower user profile rules with role flags or Django groups on the new auth user model.
