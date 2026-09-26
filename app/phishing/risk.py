from django.conf import settings

from phishing.textutil import domain_of, email_address, levenshtein

URGENCY_TERMS = (
    "password",
    "verify your account",
    "suspended",
    "gift card",
    "wire transfer",
    "action required",
    "unusual sign-in",
    "payroll",
    "urgent",
    "immediately",
    "social security",
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly"}


def _trusted(domain):
    domain = (domain or "").lower()
    trusted = settings.PHISHING_TRUSTED_DOMAINS
    if domain in trusted:
        return True
    return any(domain.endswith("." + item) for item in trusted)


def _lookalike(domain):
    domain = (domain or "").lower().rstrip(".")
    if not domain or _trusted(domain):
        return False
    for trusted in settings.PHISHING_TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]
        if brand and brand in domain and not domain.endswith("." + trusted):
            return True
        if levenshtein(domain, trusted) <= 2:
            return True
    return False


def compute_risk(parsed):
    envelope = parsed.get("envelope") or {}
    content = parsed.get("content") or {}
    artifacts = parsed.get("artifacts") or []
    text = f"{envelope.get('subject') or ''} {content.get('text') or ''}".lower()
    sender_domain = domain_of(email_address(envelope.get("from")) or envelope.get("from"))
    flags = []

    def add(code, points, detail):
        flags.append({"code": code, "points": points, "detail": detail})

    if envelope.get("had_invisible_characters"):
        add("invisible_characters", 15, "Hidden characters in the visible headers")
    if any(term in text for term in URGENCY_TERMS):
        add("urgency_language", 20, "Urgent or credential language")
    urls = [item for item in artifacts if item.get("artifact_type") == "url"]
    if urls:
        add("contains_url", 15, f"{len(urls)} link(s)")
    if len(urls) >= 5:
        add("many_urls", 10, "Large link set")
    if any(domain_of(item.get("value")) in SHORTENERS for item in urls):
        add("url_shortener", 15, "Shortened link")
    if sender_domain and not _trusted(sender_domain):
        add("external_sender", 10, sender_domain)
    if _lookalike(sender_domain):
        add("lookalike_domain", 25, sender_domain)
    reply_domain = domain_of(envelope.get("reply_to"))
    if reply_domain and sender_domain and reply_domain != sender_domain:
        add("reply_to_mismatch", 15, reply_domain)
    if "login" in text and "http" in text and sender_domain and not _trusted(sender_domain):
        add("credential_lure", 20, "External login lure")
    if _trusted(sender_domain) and "gift card" in text:
        add("internal_gift_card", 25, "Gift-card request from a trusted domain")

    score = min(100, sum(item["points"] for item in flags))
    return score, flags
