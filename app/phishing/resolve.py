import logging
import threading
from datetime import timedelta

from django.db import close_old_connections, transaction
from django.utils import timezone

from phishing.gmail_service import (
    fetch_mailbox_for_report,
    fetch_raw_message,
    gmail_delegation_configured,
    mailbox_allowed,
)
from phishing.ingest import apply_parsed_email
from phishing.models import PhishingReport
from phishing.parse import assemble_parsed_email, parse_mime

logger = logging.getLogger(__name__)
STALE_AFTER = timedelta(minutes=10)


def mark_fetch(report, status, error=""):
    metadata = dict(report.metadata or {})
    metadata["rfc822_fetch_status"] = status
    if error:
        metadata["rfc822_fetch_error"] = error[:500]
    else:
        metadata.pop("rfc822_fetch_error", None)
    report.metadata = metadata
    report.rfc822_fetch_status = status
    report.save(update_fields=["metadata", "rfc822_fetch_status", "updated_at"])


def execute_resolve(report_id):
    report = PhishingReport.objects.get(pk=report_id)
    if report.rfc822_fetch_status == "ok" and report.rfc822_message_id:
        return report
    if not gmail_delegation_configured():
        mark_fetch(report, "skipped", "Gmail service account is not configured.")
        return report
    mailbox = fetch_mailbox_for_report(report)
    message_id = report.gmail_message_id
    if not mailbox or not message_id:
        mark_fetch(report, "error", "No mailbox available for this message id.")
        return report
    if not mailbox_allowed(mailbox):
        mark_fetch(report, "error", "Mailbox domain is not allowed for delegation.")
        return report
    try:
        raw = fetch_raw_message(mailbox, message_id)
        reported, original = parse_mime(raw)
        metadata = report.metadata or {}
        if metadata.get("reported_as_forward") and original is None:
            original = None
        parsed = assemble_parsed_email(
            gmail_message_id=message_id,
            reported=reported,
            original=original,
        )
        report.message_body = raw[:500000]
        report.save(update_fields=["message_body", "updated_at"])
        apply_parsed_email(report, parsed)
        report.refresh_from_db()
        mark_fetch(report, "ok")
    except Exception as exc:
        status = _http_status(exc)
        if status == 404:
            mark_fetch(report, "not_found", "Gmail message was not found in the impersonated mailbox.")
        else:
            logger.exception("RFC822 resolve failed for report %s", report_id)
            mark_fetch(report, "error", str(exc) or exc.__class__.__name__)
    return report


def _http_status(exc):
    resp = getattr(exc, "resp", None)
    status = getattr(resp, "status", None)
    if status is None:
        status = getattr(exc, "status_code", None)
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def claim_report(report_id):
    updated = PhishingReport.objects.filter(pk=report_id, rfc822_fetch_status="pending").update(
        rfc822_fetch_status="running",
        updated_at=timezone.now(),
    )
    return updated == 1


def claim_batch(limit):
    cutoff = timezone.now() - STALE_AFTER
    PhishingReport.objects.filter(rfc822_fetch_status="running", updated_at__lt=cutoff).update(
        rfc822_fetch_status="pending"
    )
    pending_ids = list(
        PhishingReport.objects.filter(rfc822_fetch_status="pending").order_by("id").values_list("id", flat=True)[:limit]
    )
    claimed = []
    for report_id in pending_ids:
        if claim_report(report_id):
            claimed.append(report_id)
    return claimed


def _kick(report_id):
    close_old_connections()
    try:
        if claim_report(report_id):
            execute_resolve(report_id)
    except Exception:
        logger.exception("Background RFC822 resolve failed for report %s", report_id)
    finally:
        close_old_connections()


def queue_rfc822_resolve(report):
    if report.rfc822_fetch_status == "ok" and report.rfc822_message_id:
        return
    if report.rfc822_fetch_status in {"running", "error", "not_found"}:
        return
    if not gmail_delegation_configured():
        mark_fetch(report, "skipped", "Gmail service account is not configured.")
        return
    if report.rfc822_fetch_status != "pending":
        PhishingReport.objects.filter(pk=report.pk).update(
            rfc822_fetch_status="pending",
            updated_at=timezone.now(),
        )
    report_id = report.pk

    def start():
        threading.Thread(target=_kick, args=(report_id,), daemon=True).start()

    transaction.on_commit(start)
