# Google Apps Script clients

Two deployed scripts integrate with Watchtower phishing APIs. They are **not** part of the Django container; update Script Properties and redeploy when cutting over to a standalone service.

## Script inventory

| File in repo | Role |
|--------------|------|
| `scripts/temp_phishing_reporter_ui.gs` | Gmail **add-on** UI: report, campaigns, feedback, unread scan, labels |
| `scripts/watchtowerapi@wahsk12.org_script` | **Group ingest**: hourly scan of phishing@ forwards in ingest mailbox |
| `phishing/scripts/gmail_phishing_webhook.gs` | Older reference webhook; confirm whether still deployed before migration |

## Add-on: `temp_phishing_reporter_ui.gs`

### Config (`PHISH_CONFIG`)

| Key | Example | Purpose |
|-----|---------|---------|
| `WEBHOOK_URL` | `https://watchtower.washk12.org/api/phishing/gmail-report/` | POST new report |
| `CAMPAIGNS_URL` | `…/api/phishing/reported-campaigns/` | GET campaign fingerprints |
| `FEEDBACK_URL` | `…/api/phishing/campaign-feedback/` | POST agree/disagree |
| `CAMPAIGNS_HOURS` | 24 | Backend query window (1–168) |
| `CAMPAIGNS_CACHE_TTL_SEC` | 120 | ScriptCache TTL for campaign list |
| `UNREAD_CHECK_LIMIT` | 20 | Max unread threads labeled per homepage load |
| `WEBHOOK_SECRET` | *(Script Property)* | API client session token |

### Auth pitfall

- **`WEBHOOK_SECRET`** must be the **AuthorizedMobileDeviceModel** session key whose user (or acts-as user) has dashboard rule **`phishing_gmail_report_api`**.
- This is **not** `EMAIL_WEBHOOK_SECRET` used by generic email webhooks.
- Token is sent as `Authorization: Bearer`, `X-Session-Token`, and duplicated in JSON body as `session` / `apiKey` because UrlFetchApp may strip headers.

### Report flow

1. User opens message → add-on reads `GmailApp.getMessageById` / `message.getId()`.
2. POST body includes `messageId`, `reporter` (active user email), optional `originalMessageId` when user picks inner mail in forward UI.
3. On success, show `display` block from JSON (title/subtitle/detail).
4. Duplicate responses include full `analysis` (verdict, threat score, tier labels).

### Campaign matching (`findCampaignMatch_`)

On message open and unread scan, script matches open mail against GET `campaigns[]`:

1. Gmail internal ids in `gmail_message_ids` (reported wrapper + peers).
2. Normalized RFC822 keys in `rfc822_message_id_keys` / `rfc822_message_id_key`.
3. Forward parsing: extract inner From, Subject, Message-ID from body/headers.
4. Heuristic: `origin_sender` + normalized subject (prefix similarity, `[External]` strip).
5. Card view fields when API returns clustered metadata.

### Labels

- Base label **`Reported`** when any district report matches (even single report).
- Tier labels (e.g. multiple reports / elevated score) use separate naming in script.
- **`normalizeGmailLabelColor_`**: Gmail only accepts palette hex values; custom colors snap to nearest allowed color.
- Labels applied to **thread** and individual **messages** when possible (`GmailApp.createLabel` fallback).

### Verdict UI (`buildVerdictSection_`)

Shows district-reported state and **`analyst_verdict`** / confidence from campaign JSON (not only heuristic tier).

### Homepage

- Fetches campaigns (global cache key `phish_campaigns_global_{hours}`).
- Runs unread scan up to `UNREAD_CHECK_LIMIT`.
- Findings list: matched vs labeled counts (honest when label apply fails).

### Feedback

POST `campaignCommunicationId` or fingerprint fields; `vote`: `agree` | `disagree`.

## Group ingest: `watchtowerapi@wahsk12.org_script`

Runs in the **ingest mailbox** (service account user that receives forwards).

Typical behavior:

1. Time-driven trigger (hourly).
2. Gmail search: forwards to `PHISHING_GMAIL_GROUP_FORWARD_ADDRESS`, unread, exclude analyzed label.
3. Dedupe per thread + reporter (script properties store seen pairs).
4. POST to **`WEBHOOK_URL`** (same as add-on) with:
   - `messageId` — id in **ingest mailbox**
   - `reporter` — parsed from forward
   - `reportSource`: `phishing_group`
   - `gmailMailbox`: ingest address
   - `reportedAsForward`: true
5. Rate limits: max threads/reports per run, pause between POSTs.
6. **`WEBHOOK_SECRET`**: same API client token as add-on.

Backend must impersonate **`gmailMailbox`** when resolving RFC822 (see [ingestion-and-message-ids.md](ingestion-and-message-ids.md)).

## Cutover checklist (scripts only)

1. Create API client + rule on new service; copy session key to both scripts’ `WEBHOOK_SECRET`.
2. Update `WEBHOOK_URL`, `CAMPAIGNS_URL`, `FEEDBACK_URL` hostnames.
3. Redeploy add-on manifest; re-authorize if OAuth scopes changed (usually unchanged).
4. Verify group script still runs as ingest user.
5. Smoke test: report from add-on, forward to group, open matching mail → label + verdict.

## OAuth vs API token

- Add-on uses **Google user session** for GmailApp only.
- Watchtower calls use **service API token**, not Google OAuth to Django.
