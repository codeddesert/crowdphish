import json
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from phishing.actors import candidates_for_report, create_profile_from_report, link_profile
from phishing.campaigns import cards_since
from phishing.constants import CONFIDENCE_LEVELS, VERDICTS
from phishing.context import user_is_analyst as analyst_check
from phishing.gmail_service import gmail_delegation_configured
from phishing.intel import (
    IntelNotConfigured,
    configured_flags,
    run_reporter_guidance,
    scan_email,
    scan_url,
    screenshot_url,
)
from phishing.models import BadActorProfile, PhishingReport
from phishing.threat import display_threat, fish_for_submission, is_phishing_incident

LATEST_INCIDENT_CACHE = "phishing:dashboard:latest_incident_summary"


def health(request):
    connection.ensure_connection()
    return JsonResponse({"ok": True, "gmail": gmail_delegation_configured()})


def lobby(request):
    return render(request, "lobby.html")


def learn(request):
    return render(request, "learn.html")


def staff_required(view):
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            from django.contrib.auth.views import redirect_to_login

            return redirect_to_login(request.get_full_path())
        if not analyst_check(request.user):
            return render(request, "forbidden.html", status=403)
        return view(request, *args, **kwargs)

    return wrapped


def _latest_incident():
    cached = cache.get(LATEST_INCIDENT_CACHE)
    if cached is not None:
        return cached or None
    reports = PhishingReport.objects.select_related("submission").order_by("-reported_at")[
        : settings.PHISHING_LATEST_INCIDENT_SCAN_MAX
    ]
    summary = None
    for report in reports:
        submission = getattr(report, "submission", None)
        if submission and is_phishing_incident(submission):
            score, level = display_threat(submission)
            summary = {
                "report_id": report.id,
                "subject": (submission.parsed_email or {}).get("envelope", {}).get("subject") or report.message_title,
                "origin_sender": report.origin_sender,
                "threat_score": score,
                "threat_level": level,
                "analyst_verdict": submission.analyst_verdict,
            }
            break
    cache.set(LATEST_INCIDENT_CACHE, summary or {}, 60)
    return summary


def _load_report(report_id):
    return get_object_or_404(
        PhishingReport.objects.select_related("submission", "submission__analyst_verdict_by").prefetch_related(
            "submission__artifacts",
            "submission__intel_scans",
            "bad_actor_links__profile",
        ),
        pk=report_id,
    )


def _read_body(request):
    if request.content_type and "application/json" in request.content_type:
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None
    return request.POST


@staff_required
def phishing_dashboard(request):
    try:
        days = int(request.GET.get("days") or settings.PHISHING_LIST_DEFAULT_DAYS)
    except ValueError:
        days = settings.PHISHING_LIST_DEFAULT_DAYS
    days = max(1, min(days, 90))
    from django.utils import timezone

    since = timezone.now() - timedelta(days=days)
    cards = cards_since(since)
    query = (request.GET.get("q") or "").strip()
    verdict = (request.GET.get("verdict") or "").strip()
    if query:
        needle = query.lower()
        cards = [
            card
            for card in cards
            if needle in (card["subject"] or "").lower() or needle in (card["origin_sender"] or "").lower()
        ]
    if verdict in VERDICTS:
        cards = [card for card in cards if card["analyst_verdict"] == verdict]
    paginator = Paginator(cards, settings.PHISHING_LIST_PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page") or 1)
    return render(
        request,
        "phishing/dashboard.html",
        {
            "cards": page,
            "page_obj": page,
            "days": days,
            "query": query,
            "verdict": verdict,
            "verdicts": VERDICTS,
            "latest": _latest_incident(),
            "gmail_ready": gmail_delegation_configured(),
        },
    )


@staff_required
def phishing_incident_detail(request, report_id):
    report = _load_report(report_id)
    submission = report.submission
    score, level = display_threat(submission)
    return render(
        request,
        "phishing/incident.html",
        {
            "report": report,
            "submission": submission,
            "artifacts": list(submission.artifacts.all()),
            "scans": list(submission.intel_scans.all()[:30]),
            "score": score,
            "level": level,
            "fish": fish_for_submission(submission),
            "is_incident": is_phishing_incident(submission),
            "verdicts": VERDICTS,
            "confidence_levels": [item for item in CONFIDENCE_LEVELS if item],
            "candidates": candidates_for_report(report),
            "linked_profiles": [link.profile for link in report.bad_actor_links.all()],
            "intel": configured_flags(),
            "body_excerpt": (report.message_body or submission.parsed_email.get("content", {}).get("text") or "")[:8000],
        },
    )


@staff_required
@require_POST
def phishing_incident_set_verdict(request, report_id):
    report = _load_report(report_id)
    data = _read_body(request)
    wants_json = request.content_type and "application/json" in request.content_type
    if data is None:
        return JsonResponse({"success": False, "error": "Invalid JSON."}, status=400)
    verdict = str(data.get("analyst_verdict") or "").strip().lower()
    confidence = str(data.get("analyst_confidence") or "").strip().lower()
    notes = str(data.get("analyst_notes") or "")
    if verdict not in VERDICTS:
        if wants_json:
            return JsonResponse({"success": False, "error": "Invalid verdict."}, status=400)
        messages.error(request, "Choose a verdict.")
        return redirect("phishing:incident", report_id=report.id)
    submission = report.submission
    submission.analyst_verdict = verdict
    submission.analyst_confidence = confidence if confidence in CONFIDENCE_LEVELS else ""
    submission.analyst_notes = notes
    submission.analyst_verdict_by = request.user
    from django.utils import timezone

    submission.analyst_verdict_at = timezone.now()
    submission.save()
    cache.delete(LATEST_INCIDENT_CACHE)
    if wants_json:
        score, level = display_threat(submission)
        return JsonResponse(
            {
                "success": True,
                "analyst_verdict": verdict,
                "analyst_confidence": submission.analyst_confidence,
                "threat_score": score,
                "threat_level": level,
            }
        )
    messages.success(request, "Verdict saved.")
    return redirect("phishing:incident", report_id=report.id)


@staff_required
@require_POST
def phishing_bad_actor_match(request, report_id):
    report = _load_report(report_id)
    rows = [
        {"id": profile.id, "name": profile.name}
        for profile in candidates_for_report(report)
    ]
    return JsonResponse({"success": True, "candidates": rows})


@staff_required
@require_POST
def phishing_bad_actor_associate(request, report_id):
    report = _load_report(report_id)
    data = _read_body(request) or {}
    try:
        profile = BadActorProfile.objects.get(pk=int(data.get("profile_id")))
    except (BadActorProfile.DoesNotExist, TypeError, ValueError):
        messages.error(request, "Profile not found.")
        return redirect("phishing:incident", report_id=report.id)
    link_profile(profile, report)
    messages.success(request, f"Linked {profile.name}.")
    return redirect("phishing:incident", report_id=report.id)


@staff_required
@require_POST
def phishing_bad_actor_create(request, report_id):
    report = _load_report(report_id)
    data = _read_body(request) or {}
    profile = create_profile_from_report(report, name=str(data.get("name") or ""), notes=str(data.get("notes") or ""))
    messages.success(request, f"Created {profile.name}.")
    return redirect("phishing:incident", report_id=report.id)


@staff_required
@require_POST
def phishing_review_urls(request, report_id):
    report = _load_report(report_id)
    urls = [item.value for item in report.submission.artifacts.all() if item.artifact_type == "url"][:15]
    if not urls:
        messages.info(request, "No URLs to scan.")
        return redirect("phishing:incident", report_id=report.id)
    try:
        for url in urls:
            scan_url(report.submission, url)
    except IntelNotConfigured as exc:
        messages.error(request, str(exc))
        return redirect("phishing:incident", report_id=report.id)
    except Exception as exc:
        messages.error(request, f"URL scan failed: {exc}")
        return redirect("phishing:incident", report_id=report.id)
    messages.success(request, f"Scanned {len(urls)} URL(s).")
    return redirect("phishing:incident", report_id=report.id)


@staff_required
@require_POST
def phishing_review_emails(request, report_id):
    report = _load_report(report_id)
    addresses = [item.value for item in report.submission.artifacts.all() if item.artifact_type == "email"][:15]
    if not addresses:
        messages.info(request, "No email addresses to scan.")
        return redirect("phishing:incident", report_id=report.id)
    try:
        for address in addresses:
            scan_email(report.submission, address)
    except IntelNotConfigured as exc:
        messages.error(request, str(exc))
        return redirect("phishing:incident", report_id=report.id)
    except Exception as exc:
        messages.error(request, f"Email scan failed: {exc}")
        return redirect("phishing:incident", report_id=report.id)
    messages.success(request, f"Scanned {len(addresses)} address(es).")
    return redirect("phishing:incident", report_id=report.id)


@staff_required
@require_GET
def phishing_url_screenshot(request, report_id):
    _load_report(report_id)
    url = request.GET.get("url") or ""
    try:
        content, content_type = screenshot_url(url)
    except IntelNotConfigured as exc:
        return JsonResponse({"success": False, "error": str(exc)}, status=503)
    except Exception as exc:
        return JsonResponse({"success": False, "error": str(exc)}, status=400)
    return HttpResponse(content, content_type=content_type)


@staff_required
@require_POST
def phishing_reporter_ai(request, report_id):
    report = _load_report(report_id)
    guidance, gemini_error = run_reporter_guidance(report)
    wants_json = request.content_type and "application/json" in request.content_type
    if wants_json:
        return JsonResponse({"success": True, "guidance": guidance, "gemini_error": gemini_error})
    if gemini_error:
        messages.info(request, gemini_error)
    messages.success(request, "Reporter guidance updated.")
    return redirect("phishing:incident", report_id=report.id)
