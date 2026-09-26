import json

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from phishing.constants import ORIGIN_GMAIL_REPORT, SECRET_PAYLOAD_KEYS
from phishing.models import PhishingExtractedArtifact, PhishingReport, PhishingSubmission
from phishing.parse import stub_parsed_email
from phishing.risk import compute_risk
from phishing.textutil import domain_of, email_address, normalize_rfc822


def as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def normalize_report_source(value):
    text = (value or "").strip().lower().replace("-", "_")
    if text in {"phishing_group", "group", "group_ingest"}:
        return "phishing_group"
    return text or "addon"


def email_allowed_for_workspace(address):
    domain = domain_of(address)
    return bool(domain) and domain in settings.PHISHING_DELEGATION_ALLOWED_DOMAINS


def sanitize_payload(payload):
    if not isinstance(payload, dict):
        return {}

    def clean(value):
        if isinstance(value, dict):
            return {
                key: clean(item)
                for key, item in value.items()
                if str(key).replace("-", "_").lower() not in SECRET_PAYLOAD_KEYS
            }
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    cleaned = clean(payload)
    encoded = json.dumps(cleaned, default=str)
    if len(encoded) > 20000:
        return {"truncated": True}
    return cleaned


def gmail_fetch_mailbox(metadata, reporter_email):
    metadata = metadata or {}
    explicit = (metadata.get("gmail_fetch_mailbox") or "").strip()
    if explicit:
        return explicit
    source = (metadata.get("report_source") or "").lower()
    if source == "phishing_group":
        return settings.PHISHING_GMAIL_GROUP_INGEST_MAILBOX
    if reporter_email and email_allowed_for_workspace(reporter_email):
        return reporter_email
    return ""


def _sync_artifacts(submission, artifacts):
    PhishingExtractedArtifact.objects.filter(submission=submission).delete()
    rows = [
        PhishingExtractedArtifact(
            submission=submission,
            artifact_type=item["artifact_type"],
            role=item.get("role") or "",
            value=item.get("value") or "",
            lookup_key=item["lookup_key"],
            domain=item.get("domain") or "",
        )
        for item in artifacts
        if item.get("lookup_key")
    ]
    if rows:
        PhishingExtractedArtifact.objects.bulk_create(rows)


def _link_cluster_canonical(submission, parsed):
    digest = ((parsed.get("fingerprints") or {}).get("artifact_set_sha256")) or ""
    if not digest:
        return
    peer = (
        PhishingSubmission.objects.exclude(pk=submission.pk)
        .filter(parsed_email__fingerprints__artifact_set_sha256=digest)
        .order_by("id")
        .first()
    )
    if peer and (peer.cluster_canonical_id or peer.id) != submission.id:
        submission.cluster_canonical = peer.cluster_canonical or peer
        submission.save(update_fields=["cluster_canonical"])


def apply_parsed_email(report, parsed):
    envelope = parsed.get("envelope") or {}
    subject = (envelope.get("subject") or "").strip()
    if subject:
        report.message_title = subject[:500]
    body = (parsed.get("content") or {}).get("text") or ""
    if body:
        report.message_body = body[:500000]
    sender = email_address(envelope.get("from"))
    if sender:
        report.origin_sender = sender[:254]
    message_id = normalize_rfc822(envelope.get("message_id"))
    if message_id:
        report.rfc822_message_id = message_id[:512]
    metadata = dict(report.metadata or {})
    metadata["rfc822_message_id"] = report.rfc822_message_id
    layers = parsed.get("gmail_report_layers") or {}
    original = (layers.get("original") or {}) if isinstance(layers, dict) else {}
    original_id = normalize_rfc822(((original.get("envelope") or {}).get("message_id")))
    if original_id:
        metadata["original_rfc822_message_id"] = original_id
    reported = (layers.get("reported") or {}) if isinstance(layers, dict) else {}
    wrapper_id = normalize_rfc822(((reported.get("envelope") or {}).get("message_id")))
    if wrapper_id:
        metadata["wrapper_rfc822_message_id"] = wrapper_id
    report.metadata = metadata
    report.save()

    score, flags = compute_risk(parsed)
    submission, _created = PhishingSubmission.objects.get_or_create(report=report)
    submission.parsed_email = parsed
    submission.risk_score = score
    submission.risk_flags = flags
    submission.save(update_fields=["parsed_email", "risk_score", "risk_flags"])
    _sync_artifacts(submission, parsed.get("artifacts") or [])
    _link_cluster_canonical(submission, parsed)
    return submission


def create_gmail_report(
    *,
    message_id,
    reporter,
    report_source,
    gmail_mailbox,
    reported_as_forward,
    original_message_id,
    payload,
):
    existing = (
        PhishingReport.objects.filter(
            webhook_origin=ORIGIN_GMAIL_REPORT,
            gmail_message_id=message_id,
        )
        .order_by("-reported_at")
        .first()
    )
    if existing:
        return existing, False

    reporter_email = (reporter or "").strip().lower()
    source = normalize_report_source(report_source)
    metadata = {
        "source": "gmail_message_id_report",
        "gmail_message_id": message_id,
        "email_sender": reporter_email,
        "original_payload": sanitize_payload(payload),
        "report_source": source,
        "reported_as_forward": bool(reported_as_forward),
    }
    if gmail_mailbox:
        metadata["gmail_fetch_mailbox"] = gmail_mailbox.strip()
    elif source == "phishing_group":
        metadata["gmail_fetch_mailbox"] = settings.PHISHING_GMAIL_GROUP_INGEST_MAILBOX
    if original_message_id:
        metadata["gmail_original_message_id"] = original_message_id.strip()
    metadata["gmail_fetch_mailbox"] = gmail_fetch_mailbox(metadata, reporter_email)

    user = None
    if reporter_email:
        user = get_user_model().objects.filter(email__iexact=reporter_email).first()

    try:
        with transaction.atomic():
            report = PhishingReport.objects.create(
                webhook_origin=ORIGIN_GMAIL_REPORT,
                message_title=f"Message {message_id} Reported"[:500],
                metadata=metadata,
                reporter_email=reporter_email[:254],
                reporter=user,
                gmail_message_id=message_id,
                conversation_key=f"gmail-msg:{message_id}"[:180],
                rfc822_fetch_status="",
                reported_at=timezone.now(),
            )
            parsed = stub_parsed_email(message_id)
            submission = PhishingSubmission.objects.create(
                report=report,
                parsed_email=parsed,
                risk_score=0,
                risk_flags=[],
            )
            _sync_artifacts(submission, parsed["artifacts"])
    except IntegrityError:
        existing = PhishingReport.objects.filter(
            webhook_origin=ORIGIN_GMAIL_REPORT,
            gmail_message_id=message_id,
        ).first()
        if existing:
            return existing, False
        raise
    return report, True
