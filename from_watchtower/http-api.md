# HTTP API reference

Public JSON APIs are mounted in `watchtower/urls.py` under `/api/phishing/`. Staff HTML and JSON live under `/phishing/` (see [dashboard-and-analyst-workflow.md](dashboard-and-analyst-workflow.md)).

All add-on APIs are **`@csrf_exempt`**.

## Authentication (add-on APIs)

Function: `require_phishing_gmail_report_api_auth` in `phishing/gmail_report_api.py`.

### Token sources (first match wins in resolver)

| Source | Example |
|--------|---------|
| `Authorization: Bearer <token>` | Standard |
| `X-Session-Token` | Mobile/API clients |
| `X-API-Key` | Alternate header |
| Query `?session=` | GET campaigns |
| JSON body | `session`, `apiKey`, `api_key`, `sessionToken`, `session_token` |

Resolution: `watchtower.api_client_access.resolve_api_client_auth` → Django user + optional `AuthorizedMobileDeviceModel`.

### Authorization rule

User must pass `has_phishing_gmail_report_api_access` → dashboard rule **`phishing_gmail_report_api`** (`watchtower/feature_access.py`).

### Errors

| HTTP | Body |
|------|------|
| 401 | `{"success": false, "error": "Authentication required."}` |
| 403 | `{"success": false, "error": "Forbidden."}` |

---

## POST `/api/phishing/gmail-report/`

Handler: `api_phishing_gmail_report`.

### Request

```json
{
  "messageId": "19abc…",
  "reporter": "staff@washk12.org",
  "reportSource": "phishing_group",
  "gmailMailbox": "watchtowerapi@washk12.org",
  "reportedAsForward": true,
  "originalMessageId": "optional-inner-id",
  "session": "<api-client-token>"
}
```

Field aliases: `message_id`, `from`, `sender_email`, `report_source`, `gmail_mailbox`, `fetchMailbox`, `reported_as_forward`, `original_message_id`.

### Response: created (200)

```json
{
  "success": true,
  "status": "created",
  "message": "Report received…",
  "display": {
    "title": "Report Received",
    "subtitle": "Queued for Analysis",
    "detail": "…",
    "notification_text": "…"
  },
  "communication_id": 2010,
  "submission_id": 2010,
  "message_id": "19abc…",
  "duplicate_ignored": false
}
```

Note: `submission_id` equals `communication_id` (PK is Communication).

### Response: duplicate (200)

```json
{
  "success": true,
  "status": "duplicate",
  "message": "<human summary>",
  "display": { },
  "communication_id": 2008,
  "submission_id": 2008,
  "message_id": "19abc…",
  "duplicate_ignored": true,
  "analysis": {
    "summary": "…",
    "verdict": "phishing",
    "threat_score": 72,
    "display": { }
  }
}
```

### Errors

| HTTP | Condition |
|------|-----------|
| 400 | Invalid JSON, missing `messageId`, group ingest missing reporter/mailbox |

Side effect: may call `defer_rfc822_message_id_resolve(communication_id)` when SA configured.

---

## GET `/api/phishing/reported-campaigns/`

Handler: `api_phishing_reported_campaigns`.

### Query

| Param | Default | Range |
|-------|---------|-------|
| `hours` | 24 | 1–168 |
| `session` | — | Auth token for GET |

### Response (200)

```json
{
  "success": true,
  "hours": 24,
  "generated_at": "2026-09-25T12:00:00-06:00",
  "campaign_count": 3,
  "campaigns": [
    {
      "communication_id": 2010,
      "threat_score": 65,
      "threat_level": "elevated",
      "origin_sender": "attacker@evil.example",
      "subject": "Payroll update",
      "subject_normalized": "payroll update",
      "rfc822_message_id": "<id@evil.example>",
      "rfc822_message_id_key": "id@evil.example",
      "rfc822_message_id_keys": ["id@evil.example", "…"],
      "gmail_message_ids": ["19abc…"],
      "origin_at": "2026-09-24T09:00:00-06:00",
      "match_window_hours": 2,
      "report_count": 4,
      "analyst_verdict": "phishing",
      "analyst_confidence": "high",
      "analyst_notes": "",
      "analyst_verdict_at": "2026-09-25T10:00:00-06:00",
      "contributions": { "agree": 2, "disagree": 0 }
    }
  ]
}
```

`contributions` added per campaign from `PhishingCampaignContribution` aggregates.

---

## POST `/api/phishing/campaign-feedback/`

Handler: `api_phishing_campaign_feedback`.

### Request

```json
{
  "campaignCommunicationId": 2010,
  "vote": "agree",
  "reporter": "user@washk12.org",
  "messageId": "19xyz…",
  "rfc822MessageId": "<optional>",
  "originSender": "attacker@evil.example",
  "subject": "Payroll update",
  "hours": 168
}
```

If `campaignCommunicationId` omitted, server resolves via `find_campaign_communication_id_for_feedback` using RFC822 and/or origin+subject within `hours` (default 168).

`vote` aliases: `feedback`. Values normalized to agree/disagree.

### Response (200)

```json
{
  "success": true,
  "campaign_communication_id": 2010,
  "vote": "agree",
  "created": true
}
```

Exact keys from `record_campaign_contribution` — see `phishing/campaign_contributions.py`.

### Errors

| HTTP | Condition |
|------|-----------|
| 400 | Missing reporter, invalid vote, campaign not found |

---

## Staff routes (`phishing/urls.py`)

Require Django **session login** + `has_phishing_mail_access` unless noted.

| Method | Path | Handler | Notes |
|--------|------|---------|-------|
| GET | `/phishing/` | `phishing_dashboard` | Campaign cards, filters |
| GET | `/phishing/incidents/<id>/` | `phishing_incident_detail` | Review UI |
| POST | `/phishing/incidents/<id>/verdict/` | `phishing_incident_set_verdict` | JSON or form: verdict, confidence, notes |
| POST | `…/bad-actor/match/` | `phishing_bad_actor_match` | Candidate profiles |
| POST | `…/bad-actor/associate/` | Link profile |
| POST | `…/bad-actor/create/` | New BadActorProfile |
| POST | `…/review-urls/analyze/` | IPQS + VT URL scans |
| POST | `…/review-emails/analyze/` | IPQS email validation |
| GET | `…/url-screenshot/` | ApiFlash screenshot |
| POST | `…/reporter-ai-guidance/run/` | Internal + Gemini reporter AI |

Legacy URL aliases redirect or duplicate POST handlers under `incidents/report/` and `mail/submission/`.

### Verdict POST (conceptual body)

```json
{
  "analyst_verdict": "phishing",
  "analyst_confidence": "high",
  "analyst_notes": "Credential harvest"
}
```

Persists on `PhishingSubmission`; busts dashboard caches.

---

## Legacy email webhook (Watchtower)

`POST /api/email-webhook/` (or configured path) with `webhook_origin` containing `phishing` still invokes `ingest_phishing_submission` in `watchtower/views.py`. Not used by current add-on; document for migration/proxy decision only.

---

## Standalone service notes

- Preserve URL paths if possible to avoid simultaneous Apps Script + mobile client changes.
- Replace `communication_id` in JSON with `report_id` only if clients are updated together.
- Implement equivalent API client model or static bearer tokens with scoped rules.
