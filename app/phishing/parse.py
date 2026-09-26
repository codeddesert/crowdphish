import re
from email import policy
from email.parser import Parser

from phishing.textutil import (
    domain_of,
    email_address,
    extract_emails,
    extract_urls,
    normalize_rfc822,
    sha256_text,
    strip_invisible,
)

FORWARD_SPLIT = re.compile(
    r"-{5,}\s*Forwarded message\s*-{5,}|Begin forwarded message:|-{5,}\s*Original Message\s*-{5,}",
    re.IGNORECASE,
)
TAG_BLOCK = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
TAG = re.compile(r"(?s)<[^>]+>")


def html_to_text(html):
    text = TAG_BLOCK.sub(" ", html or "")
    text = TAG.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def is_forward_text(text):
    return bool(FORWARD_SPLIT.search(text or ""))


def _header_map(lines):
    folded = []
    for line in lines:
        if line[:1] in " \t" and folded:
            folded[-1] = folded[-1] + " " + line.strip()
        else:
            folded.append(line)
    headers = {}
    for line in folded:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def parse_forward_body(text):
    raw = text or ""
    match = FORWARD_SPLIT.search(raw)
    if not match:
        return None
    original = raw[match.end() :].lstrip()
    header_lines = []
    body_lines = []
    in_body = False
    started = False
    for line in original.splitlines():
        if not started and not line.strip():
            continue
        started = True
        if not in_body and not line.strip():
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            if ":" not in line and header_lines:
                in_body = True
                body_lines.append(line)
            else:
                header_lines.append(line)
    headers = _header_map(header_lines)
    if not headers.get("from") and not headers.get("subject"):
        return None
    body = "\n".join(body_lines).strip()
    return envelope_from_headers(headers, body)


def envelope_from_headers(headers, body="", html=""):
    subject, hidden_subject = strip_invisible(headers.get("subject") or "")
    sender, hidden_from = strip_invisible(headers.get("from") or "")
    text = body or ""
    if not text and html:
        text = html_to_text(html)
    return {
        "envelope": {
            "from": sender,
            "to": headers.get("to") or "",
            "subject": subject,
            "date": headers.get("date") or "",
            "message_id": headers.get("message-id") or "",
            "reply_to": headers.get("reply-to") or "",
            "had_invisible_characters": hidden_subject or hidden_from,
        },
        "content": {"text": text[:20000], "html": (html or "")[:40000]},
    }


def _part_text(part):
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        content = payload.decode(charset, errors="replace")
    return str(content or "")


def parse_mime(raw):
    message = Parser(policy=policy.default).parsestr(raw or "")
    texts = []
    htmls = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                texts.append(_part_text(part))
            elif ctype == "text/html":
                htmls.append(_part_text(part))
    else:
        body = _part_text(message)
        if message.get_content_type() == "text/html":
            htmls.append(body)
        else:
            texts.append(body)
    headers = {key.lower(): str(value) for key, value in message.items()}
    text = "\n".join(texts).strip()
    html = "\n".join(htmls).strip()
    reported = envelope_from_headers(headers, text, html)
    original = parse_forward_body(reported["content"]["text"]) or parse_forward_body(html_to_text(html))
    return reported, original


def build_artifacts(envelope, content, gmail_message_id=""):
    artifacts = []
    seen = set()

    def add(artifact_type, role, value, lookup_key=None):
        key = (lookup_key if lookup_key is not None else value).strip().lower()
        if not key:
            return
        marker = (artifact_type, key)
        if marker in seen:
            return
        seen.add(marker)
        artifacts.append(
            {
                "artifact_type": artifact_type,
                "role": role,
                "value": (value or "")[:2000],
                "lookup_key": key[:512],
                "domain": domain_of(value)[:255],
            }
        )

    if gmail_message_id:
        add("msg_id", "gmail_internal", gmail_message_id, gmail_message_id.lower())
    message_id = normalize_rfc822(envelope.get("message_id"))
    if message_id:
        add("msg_id", "header", envelope.get("message_id") or message_id, message_id)
    sender = email_address(envelope.get("from"))
    if sender:
        add("email", "sender", sender, sender)
    blob = f"{content.get('text') or ''} {html_to_text(content.get('html') or '')}"
    for addr in extract_emails(blob)[:50]:
        add("email", "body", addr, addr)
    for url in extract_urls(blob)[:100]:
        add("url", "body", url, url.lower())
    return artifacts


def fingerprint(artifacts):
    parts = sorted(f"{item['artifact_type']}:{item['lookup_key']}" for item in artifacts)
    if not parts:
        return ""
    return sha256_text("\n".join(parts))


def assemble_parsed_email(*, gmail_message_id, reported, original=None):
    effective = original or reported or {"envelope": {}, "content": {"text": "", "html": ""}}
    artifacts = build_artifacts(
        effective.get("envelope") or {},
        effective.get("content") or {},
        gmail_message_id=gmail_message_id,
    )
    if reported and original:
        existing = {(item["artifact_type"], item["lookup_key"]) for item in artifacts}
        for item in build_artifacts(reported.get("envelope") or {}, {"text": "", "html": ""}, ""):
            marker = (item["artifact_type"], item["lookup_key"])
            if item["role"] == "header" and marker not in existing:
                artifacts.append(item)
                existing.add(marker)
    return {
        "schema_version": 1,
        "source": "gmail_message_id_report",
        "envelope": effective.get("envelope") or {},
        "content": effective.get("content") or {"text": "", "html": ""},
        "artifacts": artifacts,
        "fingerprints": {"artifact_set_sha256": fingerprint(artifacts)},
        "gmail_report_layers": {
            "reported": reported,
            "original": original,
        },
    }


def stub_parsed_email(gmail_message_id):
    artifact = {
        "artifact_type": "msg_id",
        "role": "gmail_internal",
        "value": gmail_message_id,
        "lookup_key": gmail_message_id.lower(),
        "domain": "",
    }
    return {
        "schema_version": 1,
        "source": "gmail_message_id_report",
        "envelope": {"from": "", "to": "", "subject": "", "date": "", "message_id": "", "reply_to": ""},
        "content": {"text": "", "html": ""},
        "artifacts": [artifact],
        "fingerprints": {},
        "gmail_report_layers": None,
    }
