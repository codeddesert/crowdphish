import json

import requests
from django.conf import settings
from django.utils import timezone
from urllib.parse import quote

from phishing.models import IntelScan
from phishing.textutil import refang
from phishing.threat import display_threat


class IntelNotConfigured(Exception):
    pass


def configured_flags():
    return {
        "ipqs": bool(settings.IPQUALITYSCORE_API_KEY),
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "apiflash": bool(settings.APIFLASH_API_KEY),
        "gemini": bool(settings.GEMINI_API_KEY or settings.AI_SERVICE_URL),
    }


def _store(submission, kind, provider, lookup_key, result):
    return IntelScan.objects.create(
        submission=submission,
        kind=kind,
        provider=provider,
        lookup_key=(lookup_key or "")[:512],
        result=result,
    )


def _get_json(url, headers=None, params=None):
    response = requests.get(url, headers=headers, params=params, timeout=25)
    try:
        payload = response.json()
    except ValueError:
        payload = {"status_code": response.status_code, "body": response.text[:2000]}
    if response.status_code >= 400:
        payload = {"status_code": response.status_code, "body": payload}
    return payload


def scan_email(submission, address):
    key = settings.IPQUALITYSCORE_API_KEY
    if not key:
        raise IntelNotConfigured("IPQualityScore is not configured.")
    payload = _get_json(f"https://ipqualityscore.com/api/json/email/{key}/{quote(address)}")
    return _store(submission, "email", "ipqs", address.lower(), payload)


def scan_url(submission, url):
    cleaned = refang(url)
    stored = []
    if settings.IPQUALITYSCORE_API_KEY:
        payload = _get_json(
            f"https://ipqualityscore.com/api/json/url/{settings.IPQUALITYSCORE_API_KEY}/{quote(cleaned, safe='')}"
        )
        stored.append(_store(submission, "url", "ipqs", cleaned.lower(), payload))
    if settings.VIRUSTOTAL_API_KEY:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            data={"url": cleaned},
            timeout=25,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"status_code": response.status_code, "body": response.text[:2000]}
        stored.append(_store(submission, "url", "virustotal", cleaned.lower(), payload))
    if not stored:
        raise IntelNotConfigured("No URL intel provider is configured.")
    return stored


def screenshot_url(url):
    key = settings.APIFLASH_API_KEY
    if not key:
        raise IntelNotConfigured("ApiFlash is not configured.")
    cleaned = refang(url)
    if not cleaned.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    response = requests.get(
        "https://api.apiflash.com/v1/urltoimage",
        params={"access_key": key, "url": cleaned, "fresh": "true"},
        timeout=45,
    )
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "image/jpeg")
    return response.content, content_type.split(";")[0]


def heuristic_guidance(report):
    submission = report.submission
    score, level = display_threat(submission)
    flags = ", ".join(item.get("code", "") for item in submission.risk_flags) or "none"
    return {
        "source": "heuristic",
        "summary": (
            f"Heuristic score {score} ({level}). Flags: {flags}. "
            "Tell the reporter not to click links, open attachments, or reply with credentials "
            "until an analyst confirms the verdict."
        ),
        "user_action": "Forward the message to the phishing mailbox if it is still in the inbox, then leave it alone.",
    }


def _gemini_text(report):
    excerpt = (report.message_body or (report.submission.parsed_email or {}).get("content", {}).get("text") or "")[:4000]
    prompt = (
        "You are a school-district email security analyst. Classify the reported message for staff. "
        "Respond with JSON keys summary, user_action, and confidence (low, medium, or high). "
        "Describe the risk in plain language. Do not provide exploit, evasion, or attack steps.\n\n"
        f"Subject: {report.message_title}\n"
        f"Sender: {report.origin_sender}\n"
        f"Heuristic score: {report.submission.risk_score}\n"
        f"Flags: {report.submission.risk_flags}\n"
        f"Excerpt:\n{excerpt}"
    )
    if settings.AI_SERVICE_URL:
        url = settings.AI_SERVICE_URL.rstrip("/") + settings.AI_SERVICE_GEMINI_PATH
        response = requests.post(url, json={"prompt": prompt}, timeout=40)
        response.raise_for_status()
        return response.text
    if not settings.GEMINI_API_KEY:
        raise IntelNotConfigured("Gemini is not configured.")
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.GEMINI_MODEL}:generateContent?key={settings.GEMINI_API_KEY}"
    )
    response = requests.post(
        url,
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=40,
    )
    response.raise_for_status()
    data = response.json()
    parts = (((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [{}])
    return parts[0].get("text") or json.dumps(data)[:4000]


def run_reporter_guidance(report):
    submission = report.submission
    guidance = {"internal": heuristic_guidance(report)}
    submission.reporter_ai_internal_generated_at = timezone.now()
    gemini_error = ""
    try:
        text = _gemini_text(report)
        parsed = text
        stripped = text.strip()
        if stripped.startswith("```"):
            stripped = stripped.strip("`")
            stripped = stripped.split("\n", 1)[-1]
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = {"summary": text[:2000]}
        guidance["gemini"] = parsed
        submission.reporter_ai_gemini_generated_at = timezone.now()
    except IntelNotConfigured as exc:
        gemini_error = str(exc)
    except Exception as exc:
        gemini_error = str(exc)[:300]
    submission.reporter_ai_guidance_json = guidance
    submission.reporter_ai_last_request_payload = {
        "subject": report.message_title,
        "origin_sender": report.origin_sender,
        "risk_score": submission.risk_score,
    }
    submission.save(
        update_fields=[
            "reporter_ai_guidance_json",
            "reporter_ai_internal_generated_at",
            "reporter_ai_gemini_generated_at",
            "reporter_ai_last_request_payload",
        ]
    )
    return guidance, gemini_error
