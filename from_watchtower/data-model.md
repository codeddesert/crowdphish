# Data model

## Current schema (Watchtower)

Phishing analysis is **1:1 with `communications.Communication`**. The communication row is the primary key for URLs, API ids, and foreign keys.

### `communications.Communication` (relevant fields)

| Field | Phishing usage |
|-------|----------------|
| `id` | Public `communication_id` everywhere |
| `com_type` | `'webhook'` |
| `webhook_origin` | `Gmail_Phishing_MessageId_Report` or legacy `*phishing*` |
| `message_title` | Subject or synthetic title |
| `message_body` | Raw MIME/text after RFC822 resolve |
| `metadata` | JSON: gmail ids, rfc822, report_source, fetch status, original_payload |
| `message_origin` | FK User (reporter) when resolvable |
| `parent_communication` | Null for phishing ingest parents |
| `timestamp` | Report time |

### `phishing.PhishingSubmission`

PK = FK to `Communication` (`primary_key=True` on `communication`).

| Field | Purpose |
|-------|---------|
| `parsed_email` | Versioned JSON parse (envelope, content, artifacts, layers) |
| `risk_score`, `risk_flags` | Ingest heuristics |
| `cluster_canonical` | Self-FK; peers point to canonical parsed blob |
| `analyst_verdict` | unknown / phishing / malware / spam / legitimate |
| `analyst_confidence` | low / medium / high |
| `analyst_notes` | Free text |
| `analyst_verdict_by`, `analyst_verdict_at` | Audit |
| `reporter_ai_guidance_json` | Cached AI output |
| `reporter_ai_*_generated_at` | Internal vs Gemini timestamps |
| `reporter_ai_last_request_payload` | Debug/audit |

### `phishing.PhishingExtractedArtifact`

FK `submission` → `PhishingSubmission`.

Unique per `(submission, artifact_type, lookup_key)`.

Types: `email`, `url`, `msg_id`. Roles include `gmail_internal`, `header`, `sender`, `body`, forward-related roles.

Indexed for campaign fingerprint collection and duplicate analysis.

### `phishing.PhishingCampaignContribution`

FK to campaign communication; stores reporter agree/disagree votes from add-on feedback API.

---

## Target standalone schema (recommended)

Decouple from Watchtower communications and user-communication wrappers.

### `PhishingReport` (replaces Communication for phishing)

Suggested columns:

| Column | Notes |
|--------|-------|
| `id` | BigAutoField PK |
| `legacy_communication_id` | Nullable int for migration |
| `webhook_origin` | Same constants as today |
| `message_title` | |
| `message_body` | |
| `metadata` | JSONField, same keys |
| `reporter_email` | Denormalized |
| `reporter_user_id` | Nullable FK AUTH_USER |
| `conversation_key` | e.g. `gmail-msg:…` |
| `reported_at` | DateTime |
| `created_at`, `updated_at` | |

### `PhishingSubmission`

Change PK to own `id`; **`OneToOneField(PhishingReport)`** instead of Communication PK.

Keep all analysis fields unchanged.

### `PhishingExtractedArtifact`

FK `submission_id` unchanged logically.

### `PhishingCampaignContribution`

FK `campaign_report_id` → `PhishingReport`.

### Optional tables

| Table | Purpose |
|-------|---------|
| `PhishingReportEvent` | Audit trail (resolve started/finished, fetch errors) |
| `PhishingCampaign` | Materialized card row for fast dashboard |
| `ApiClientToken` | Replace AuthorizedMobileDeviceModel for add-on |

### Migration mapping

```
Communication.id  →  PhishingReport.legacy_communication_id
                  →  PhishingReport.id (new) or preserve id if copying wholesale

PhishingSubmission.communication_id  →  PhishingReport.id
```

Update all URL patterns to use `report_id` or keep integer ids stable via preserved PKs.

### What not to port

- `UserCommunicationModel` — query `PhishingReport` directly.
- `NagiosMailDetail` and non-phishing communication subtypes.
- Parent/child thread model unless replaying generic mail UI.

---

## JSON: `parsed_email` (stable contract)

Document for downstream parsers:

- `schema_version` (int)
- `source` — `gmail_message_id_report` | webhook variants
- `envelope` — from, to, subject, dates, message ids
- `content` — text/html excerpts
- `artifacts` — list of typed extractions
- `fingerprints` — e.g. artifact set hash for clustering
- `gmail_report_layers` — optional `{ reported: {...}, original: {...} }` after resolve

Peers with empty parse use `cluster_canonical` → canonical row’s `parsed_email`.

---

## Indexes (standalone)

Mirror current intent:

- `(risk_score, analyst_verdict)` on submission
- `lookup_key`, `domain` on artifacts
- `metadata.gmail_message_id` (GIN on JSONB in Postgres)
- `reported_at` desc for dashboard lists
