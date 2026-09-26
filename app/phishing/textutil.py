import hashlib
import re
from email.utils import parseaddr
from urllib.parse import urlparse

_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_SUBJECT_PREFIX = re.compile(r"^(re|fw|fwd)\s*:\s*", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def strip_invisible(value):
    text = value or ""
    cleaned = _INVISIBLE.sub("", text)
    return cleaned, cleaned != text


def normalize_subject(subject):
    cleaned, _hidden = strip_invisible(subject or "")
    collapsed = re.sub(r"\s+", " ", cleaned.replace("[external]", " ")).strip()
    previous = None
    while previous != collapsed:
        previous = collapsed
        collapsed = _SUBJECT_PREFIX.sub("", collapsed).strip()
    return collapsed.lower()


def normalize_rfc822(value):
    text = (value or "").strip().strip("<>").strip().lower()
    return text


def email_address(value):
    _name, addr = parseaddr(value or "")
    addr = (addr or "").strip().lower()
    if "@" not in addr:
        return ""
    return addr


def domain_of(value):
    addr = email_address(value) or (value or "").strip().lower()
    if "://" in addr:
        host = urlparse(addr).hostname or ""
        return host.lower()
    if "@" in addr:
        return addr.rsplit("@", 1)[-1]
    return addr


def extract_emails(text):
    found = []
    seen = set()
    for match in _EMAIL.findall(text or ""):
        addr = match.lower().strip(".")
        if addr not in seen:
            seen.add(addr)
            found.append(addr)
    return found


def extract_urls(text):
    found = []
    seen = set()
    for match in _URL.findall(text or ""):
        url = match.rstrip(").,;]}>\"'")
        key = url.lower()
        if key not in seen:
            seen.add(key)
            found.append(url)
    return found


def refang(url):
    text = (url or "").strip()
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("[.]", ".").replace("(.)", ".")
    return text


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def levenshtein(left, right):
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        for j, rchar in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (lchar != rchar)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]
