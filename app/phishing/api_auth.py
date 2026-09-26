import hmac

from phishing.models import ApiClient
from phishing.textutil import hash_token

BODY_TOKEN_KEYS = ("session", "apiKey", "api_key", "sessionToken", "session_token")


def token_from_request(request):
    header = request.headers.get("Authorization") or ""
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
        if token:
            return token
    for name in ("X-Session-Token", "X-API-Key"):
        token = (request.headers.get(name) or "").strip()
        if token:
            return token
    token = (request.GET.get("session") or "").strip()
    return token


def token_from_body(body):
    if not isinstance(body, dict):
        return ""
    for key in BODY_TOKEN_KEYS:
        token = body.get(key)
        if token:
            return str(token).strip()
    return ""


def client_for_token(token):
    if not token:
        return None
    digest = hash_token(token)
    client = ApiClient.objects.filter(is_active=True, token_hash=digest).first()
    if client is None:
        return None
    if not hmac.compare_digest(client.token_hash, digest):
        return None
    return client


def client_from_request(request, body=None):
    return client_for_token(token_from_request(request) or token_from_body(body))
