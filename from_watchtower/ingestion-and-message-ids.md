# Ingestion and message identifiers

Understanding identifiers is critical for extraction: the system uses **three different id concepts** that must not be conflated.

## Identifier types

| Id | Example shape | Where it lives | Used for |
|----|---------------|----------------|----------|
| **Gmail internal message id** | Opaque string from `e.gmail.messageId` / GmailApp | Reporter or ingest mailbox only | POST body `messageId`; dedupe key `metadata.gmail_message_id`; add-on campaign match |
| **RFC822 Message-ID** | `<CA...@mail.example.com>` | Email headers; global for a sent message | Campaign fingerprint; cross-mailbox matching; artifacts `role=header` |
| **Watchtower communication id** | Integer PK | `communications_communication.id` | Dashboard URLs, campaign `communication_id`, contributions FK |

**Rule:** A Gmail internal id is **not** portable between mailboxes. Group ingest POSTs the id from **watchtowerapi@…** (ingest mailbox), not the reporter’s copy.

## Primary API: POST `/api/phishing/gmail-report/`

Implementation: `phishing/gmail_report_api.py` → `api_phishing_gmail_report`.

### Request body (JSON)

Required:

- `messageId` or `message_id` — Gmail API id in the mailbox that will be impersonated for fetch.

Common optional fields:

| Field | Purpose |
|-------|---------|
| `reporter`, `from`, `sender_email` | Staff reporter email (metadata + Django user link) |
| `reportSource` / `report_source` | `phishing_group` triggers group ingest defaults |
| `gmailMailbox` / `gmail_mailbox` | Mailbox to impersonate for fetch (defaults from settings for group) |
| `reportedAsForward` / `reported_as_forward` | Forward wrapper semantics in resolve |
| `originalMessageId` / `original_message_id` | Add-on user-selected inner message (metadata) |
| `session`, `apiKey`, `api_key` | Auth fallback when Apps Script strips headers |

Secrets in body are stripped before persisting `metadata.original_payload` (`_sanitize_gmail_report_payload`).

### Auth

See [http-api.md](http-api.md). Token must map to API client with **`phishing_gmail_report_api`** rule.

### Duplicate detection

```text
Communication.objects.filter(
  com_type='webhook',
  webhook_origin='Gmail_Phishing_MessageId_Report',
  metadata__gmail_message_id=<messageId>,
).order_by('-timestamp').first()
```

If found: return HTTP 200 with `status: duplicate`, `analysis` block (verdict, threat score, display strings), `duplicate_ignored: true`. May still defer RFC822 resolve if rfc822 missing and SA configured.

### Create path

1. `message_title` ← `Message {messageId} Reported`
2. `metadata` includes at minimum:
   - `source: gmail_message_id_report`
   - `gmail_message_id`
   - `email_sender` (reporter)
   - `original_payload` (sanitized)
   - Optional: `report_source`, `gmail_fetch_mailbox`, `reported_as_forward`, `gmail_original_message_id`
3. `ingest_gmail_message_id_report()` creates `PhishingSubmission` with minimal `parsed_email` and one `PhishingExtractedArtifact` (`artifact_type=msg_id`, `role=gmail_internal`).
4. `defer_rfc822_message_id_resolve(communication.pk)` if service account configured.

## RFC822 resolve pipeline

Modules: `phishing/gmail_rfc822_resolve.py`, `phishing/gmail_service.py`, optional `gmail_original_resolve.py`.

### Mailbox selection (`gmail_fetch_mailbox_for_report_metadata`)

Order of precedence:

1. `metadata.gmail_fetch_mailbox` (group ingest)
2. Settings `PHISHING_GMAIL_GROUP_INGEST_MAILBOX` when `report_source` is group-like
3. Reporter email (add-on) if allowed for workspace delegation

Group reports **fail fetch** if code impersonates reporter only — historical bug class: `rfc822_fetch_status: not_found`.

### Fetch outcome

On success, typically updates:

- `Communication.message_body` (wrapper or full MIME text)
- `metadata.rfc822_message_id`, `original_rfc822_message_id`, gmail body fetch status fields
- Re-run `ingest_phishing_submission` with full webhook-shaped payload OR layered `parsed_email.gmail_report_layers` (reported vs original)

Forward detection: `phishing/parse.py` `is_gmail_forward_message`, `extract_forwarded_origin_metadata` — inner From, Subject, Date, Message-ID.

### Artifacts

- RFC822 id → `PhishingExtractedArtifact` with normalized `lookup_key` (`gmail_service.normalize_rfc822_lookup_key`)
- Used by `report_analysis_summary.find_best_submission_for_message_id` and campaign fingerprints

### Background execution

`defer_rfc822_message_id_resolve` starts a **daemon thread** on the web worker (`threading`). Standalone service should use a queue worker for reliability and retries.

### Ops backfill

`python manage.py resolve_phishing_gmail_rfc822 --all --limit N`

Pending rows: parent gmail-report webhooks without successful body fetch (see command help in `phishing/management/commands/resolve_phishing_gmail_rfc822.py`).

## Full-body ingest (legacy)

`watchtower/views.py` email webhook handler (~line 14592): when `webhook_origin` contains `phishing` and parent is null, calls `ingest_phishing_submission` with subject/body/from from payload.

This path may still feed **cluster auto Gemini** (`cluster_auto_pipeline.py`); gmail-report path does **not** call that defer today.

Migration options:

- Proxy legacy webhook to new service
- Retire and rely on gmail-report + group ingest only
- Port auto-pipeline trigger to post-resolve hook in new service

## Group mailbox script flow

File: `scripts/watchtowerapi@wahsk12.org_script`

1. Search `to:phishing@… is:unread -label:ZZZ_Phishing_Analyzed`
2. Dedupe: per-thread first forward per reporter (`PHISHING_THREAD_REPORTERS` script property)
3. POST to same `gmail-report` URL with:
   - `messageId` from message in **ingest mailbox**
   - `reporter` from forward metadata
   - `reportSource: 'phishing_group'`
   - `reportedAsForward: true`
   - `gmailMailbox: watchtowerapi@…`
4. Rate limits: `MAX_THREADS_PER_RUN`, `MAX_REPORTS_PER_RUN`, `PAUSE_MS_BETWEEN_REPORTS`
5. Auth: Script property **`WEBHOOK_SECRET`** = API client session key (NOT `EMAIL_WEBHOOK_SECRET`)

## Parsed email schema (conceptual)

Stored on `PhishingSubmission.parsed_email` (JSON):

- `schema_version`
- `source` (`gmail_message_id_report` or full webhook)
- `envelope` (from, message_id, rfc822_message_id, …)
- `content` (body excerpts)
- `artifacts` (emails, urls, message_ids with lookup_key)
- `fingerprints` (e.g. artifact_set_sha256 for cluster canonical linking)
- `gmail_report_layers` (optional): `reported` / `original` sub-objects after resolve

## Risk at ingest

`phishing/risk.py` `compute_risk_score(parsed)` → `risk_score`, `risk_flags` on submission. Analyst verdict later **overrides** incident classification in UI (`phishing/incidents.py` `is_phishing_incident`).

## Settings (Django)

| Setting | Default / notes |
|---------|-----------------|
| `PHISHING_GMAIL_SERVICE_ACCOUNT_FILE` | Path to SA JSON |
| `PHISHING_GMAIL_GROUP_INGEST_MAILBOX` | e.g. watchtowerapi@washk12.org |
| `PHISHING_GMAIL_GROUP_FORWARD_ADDRESS` | e.g. phishing@washk12.org |
| `PHISHING_GMAIL_ORIGINAL_SEARCH_WINDOW_HOURS` | Heuristic original search (default 2) |
| `PHISHING_GMAIL_DELEGATION_SCOPES` | Usually gmail.modify |

See [docker-and-env.md](docker-and-env.md) for full env list.
