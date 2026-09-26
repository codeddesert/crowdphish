import json

from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from phishing.analysis import CREATED_DISPLAY, summarize_phishing_report_analysis
from phishing.api_auth import client_from_request
from phishing.campaigns import find_campaign_report_id, record_contribution, reported_campaigns
from phishing.ingest import as_bool, create_gmail_report, normalize_report_source
from phishing.resolve import queue_rfc822_resolve


def _error(message, status):
    return JsonResponse({"success": False, "error": message}, status=status)


def _read_json(request):
    if not request.body:
        return {}, None
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, _error("Invalid JSON.", 400)
    if not isinstance(payload, dict):
        return None, _error("Invalid JSON.", 400)
    return payload, None


def _authorize(request, body=None):
    client = client_from_request(request, body)
    if client is None:
        return None, _error("Authentication required.", 401)
    if not client.gmail_report_api:
        return None, _error("Forbidden.", 403)
    return client, None


def _first(body, *keys):
    for key in keys:
        value = body.get(key)
        if value not in (None, ""):
            return value
    return ""


def _hours(value, default):
    if value in (None, ""):
        return default, None
    try:
        hours = int(value)
    except (TypeError, ValueError):
        return None, _error("hours must be an integer.", 400)
    if hours < 1 or hours > 168:
        return None, _error("hours must be between 1 and 168.", 400)
    return hours, None


def _report_payload(report, *, created):
    body = {
        "success": True,
        "status": "created" if created else "duplicate",
        "communication_id": report.id,
        "report_id": report.id,
        "submission_id": report.id,
        "message_id": report.gmail_message_id,
        "duplicate_ignored": not created,
    }
    if created:
        body["message"] = "Report received and queued for analysis."
        body["display"] = CREATED_DISPLAY
    else:
        analysis = summarize_phishing_report_analysis(report)
        body["message"] = analysis["summary"]
        body["display"] = analysis["display"]
        body["analysis"] = analysis
    return JsonResponse(body)


@csrf_exempt
@require_POST
def api_phishing_gmail_report(request):
    body, error = _read_json(request)
    if error:
        return error
    _client, error = _authorize(request, body)
    if error:
        return error
    message_id = str(_first(body, "messageId", "message_id")).strip()
    if not message_id or any(char.isspace() for char in message_id) or len(message_id) > 128:
        return _error("messageId is required.", 400)
    reporter = str(_first(body, "reporter", "from", "sender_email")).strip()
    source = normalize_report_source(_first(body, "reportSource", "report_source"))
    mailbox = str(_first(body, "gmailMailbox", "gmail_mailbox", "fetchMailbox")).strip()
    if source == "phishing_group" and (not reporter or not mailbox):
        return _error("Group ingest requires reporter and gmailMailbox.", 400)
    report, created = create_gmail_report(
        message_id=message_id,
        reporter=reporter,
        report_source=source,
        gmail_mailbox=mailbox,
        reported_as_forward=as_bool(_first(body, "reportedAsForward", "reported_as_forward")),
        original_message_id=str(_first(body, "originalMessageId", "original_message_id")).strip(),
        payload=body,
    )
    queue_rfc822_resolve(report)
    return _report_payload(report, created=created)


@csrf_exempt
@require_GET
def api_phishing_reported_campaigns(request):
    _client, error = _authorize(request)
    if error:
        return error
    hours, error = _hours(request.GET.get("hours"), 24)
    if error:
        return error
    campaigns = reported_campaigns(hours)
    return JsonResponse(
        {
            "success": True,
            "hours": hours,
            "generated_at": timezone.localtime().isoformat(),
            "campaign_count": len(campaigns),
            "campaigns": campaigns,
        }
    )


@csrf_exempt
@require_POST
def api_phishing_campaign_feedback(request):
    body, error = _read_json(request)
    if error:
        return error
    _client, error = _authorize(request, body)
    if error:
        return error
    reporter = str(_first(body, "reporter", "from", "sender_email")).strip().lower()
    if not reporter:
        return _error("reporter is required.", 400)
    vote = str(_first(body, "vote", "feedback")).strip().lower()
    if vote not in {"agree", "disagree"}:
        return _error("vote must be agree or disagree.", 400)
    hours, error = _hours(body.get("hours"), 168)
    if error:
        return error
    raw_id = _first(body, "campaignCommunicationId", "campaign_communication_id", "reportId", "report_id")
    report_id = None
    if raw_id not in ("", None):
        try:
            report_id = int(raw_id)
        except (TypeError, ValueError):
            return _error("campaignCommunicationId is invalid.", 400)
    resolved = find_campaign_report_id(
        report_id=report_id,
        rfc822_message_id=str(_first(body, "rfc822MessageId", "rfc822_message_id")),
        origin_sender=str(_first(body, "originSender", "origin_sender")),
        subject=str(_first(body, "subject")),
        hours=hours,
    )
    if not resolved:
        return _error("Campaign not found.", 400)
    _contribution, created = record_contribution(
        campaign_report_id=resolved,
        reporter_email=reporter,
        vote=vote,
        gmail_message_id=str(_first(body, "messageId", "message_id")).strip(),
        metadata={
            "subject": str(_first(body, "subject")),
            "origin_sender": str(_first(body, "originSender", "origin_sender")),
        },
    )
    return JsonResponse(
        {
            "success": True,
            "campaign_communication_id": resolved,
            "report_id": resolved,
            "vote": vote,
            "created": created,
        }
    )
