# Watchtower coupling inventory

Every cross-app dependency to **replace, copy, or stub** when extracting phishing to a standalone service.

## Django apps involved

| App | Relationship |
|-----|--------------|
| `phishing` | Core domain (~58 modules) |
| `communications` | **Replace** — `Communication` ORM for all ingest rows |
| `watchtower` | Auth, feature rules, mail thread UI helpers, URL mounting |
| `security` | Bad Actor + IPQS/VT/ApiFlash (**port subset**) |
| `ai_broker` | Optional sidecar for Gemini (**copy or HTTP**) |

## `phishing/` → external imports

### `communications.models.Communication`

| Module | Usage |
|--------|--------|
| `gmail_report_api.py` | Create webhook rows |
| `gmail_rfc822_resolve.py` | Load/update report rows |
| `ingest.py` | Lazy import in ingest helpers |
| `campaign_contributions.py` | FK target for campaigns |
| `report_analysis_summary.py` | Duplicate lookup |
| `cluster_alert_email.py` | Cluster membership |
| Management commands | Backfill / resolve |

**Action:** Replace with `PhishingReport` model; update all FKs and queries.

### `watchtower.feature_access`

| Function | Used in |
|----------|---------|
| `has_phishing_mail_access` | `views.py`, `dashboard.py`, `bad_actor_views.py` |
| `has_phishing_gmail_report_api_access` | `gmail_report_api.py` |
| `get_user_feature_access` | `views.py` detail context |

**Action:** Reimplement with Django groups/permissions or simple `UserProfile.can_access_phishing`.

### `watchtower.api_client_access`

| Module | Usage |
|--------|--------|
| `gmail_report_api.py` | `resolve_api_client_auth` |

**Action:** New `ApiClient` model + token validation middleware.

### `watchtower.models`

| Model | Used in |
|-------|---------|
| `AuthorizedMobileDeviceModel` | API auth (via api_client_access) |
| `UserCommunicationModel` | `views.py`, `bad_actor_views.py`, `cluster_utils.py`, `cluster_auto_pipeline.py`, `dashboard.py` |

**Action:** Query `PhishingReport` directly; drop UC wrapper.

### `watchtower.views` (large coupling)

| Symbol | Used in |
|--------|---------|
| `_build_webhook_mail_thread_items` | `views.py`, `bad_actor_views.py`, `mail_assembly.py`, `cluster_auto_pipeline.py` |
| `_build_phishing_review_email_display_blocks` | `mail_assembly.py` |
| Other display helpers | `views.py` imports bundle |

**Action:** Copy minimal thread-building logic into `phishing/mail_assembly.py` or new `phishing/thread_display.py`; remove Nagios/non-phishing branches.

### `watchtower.inbound_mail_queryset`

| Module | Usage |
|--------|--------|
| `dashboard.py` | `phishing_parent_submissions_queryset` base |

**Action:** Replace with `PhishingReport.objects.filter(...)`.

### `watchtower.registration_invites`

| Module | Usage |
|--------|--------|
| `gmail_rfc822_resolve.py`, `gmail_original_resolve.py` | `email_allowed_for_workspace` for delegation |

**Action:** Copy allowlist helper or config `PHISHING_DELEGATION_ALLOWED_DOMAINS`.

### `watchtower.dashboard_sections`

| Module | Usage |
|--------|--------|
| `cluster_auto_pipeline.py`, `cluster_alert_email.py` | `get_phishing_subject_cluster_membership` |

**Action:** Move function to `phishing/cluster_utils.py` or drop home-section-only automation.

### `watchtower.admin_utils`

| Module | Usage |
|--------|--------|
| `admin.py`, `admin_helpers.py` | JSON admin widgets, admin links |

**Action:** Use default Django admin or copy small JSON widget.

### `watchtower.request_client_ip`

| Module | Usage |
|--------|--------|
| `gmail_report_api.py` | `get_device_session_token` |

**Action:** Copy one function or read header in auth layer.

### `watchtower/urls.py`

Includes:

- `path('phishing/', include('phishing.urls'))`
- API paths to `gmail_report_api` views

**Action:** New project `urls.py` only; remove from Watchtower in phase C.

### `watchtower/views.py` (monolith)

~line 14592: legacy phishing **email webhook** ingest.

**Action:** Proxy, retire, or reimplement as internal endpoint.

### `watchtower/settings.py`

INSTALLED_APPS, middleware, template dirs, static, all `PHISHING_*` and intel keys.

**Action:** New `phishing_service/settings.py` with trimmed INSTALLED_APPS.

## `security/` imports from `phishing/`

Heavy usage in:

- `bad_actor_views.py`
- `mail_assembly.py`
- `url_screenshot.py`
- `parse.py`
- `cluster_auto_pipeline.py`
- `cluster_alert_email.py`

**Action:** Port as `security` app inside new repo or merge into `phishing/intel/`.

## Templates (Watchtower paths)

| Template | Purpose |
|----------|---------|
| `templates/watchtower/phishing_dashboard.html` | Main list |
| `templates/watchtower/phishing_incident_detail.html` | Detail |
| `templates/watchtower/partials/phishing_incident_cards.html` | Cards partial |
| `templates/watchtower/dashboard_base.html` | Layout shell |
| `templates/home/sections/phishing_incidents_section.html` | Home embed |

**Action:** New `base.html` without Watchtower sidebar; copy phishing-specific templates and static CSS.

## Static assets

- `watchtower/static/css/phishing_*.css`
- Any JS partials referenced from templates

## Tests to port or rewrite

| Path | Covers |
|------|--------|
| `phishing/tests/test_gmail_report_api.py` | API auth + ingest |
| `phishing/tests/test_gmail_rfc822_resolve.py` | Resolve |
| `phishing/tests/test_reported_campaigns_api.py` | Campaign GET |
| `phishing/tests/test_incidents.py` | Verdict/incident logic |
| `phishing/tests/test_url_screenshot.py` | ApiFlash |

Depend on `AuthorizedMobileDeviceModel`, `DashboardRuleModel` — replace fixtures with new auth models.

## Feature flags / dashboard rules

Rule slug: **`phishing_gmail_report_api`** (API).

Staff access: **`has_phishing_mail_access`** (implementation checks dashboard rules on user — see `feature_access.py` for exact rule slugs).

**Action:** Document slugs in new service RBAC table.

## Database

Shared Postgres today with `communications_*`, `watchtower_*`, `security_*`, `phishing_*`.

**Action:** Dedicated `phishing_db` with migrations generated from target schema; no FK to Watchtower tables.

## Minimal copy set (Python packages)

**Copy/adapt:**

- Entire `phishing/` package (minus test fixtures tied to Watchtower models)
- `security/` modules listed in [intel-and-ai.md](intel-and-ai.md)
- Optional `ai_broker/`

**Rewrite from scratch (smaller than copying):**

- URL routing project shell
- API client auth (~200 lines)
- `PhishingReport` model + queryset replacements
- Dashboard base template

**Do not copy:**

- Bulk of `watchtower/views.py`
- Communications app unrelated models
- Nagios, gatekeeper, TMS, etc.
