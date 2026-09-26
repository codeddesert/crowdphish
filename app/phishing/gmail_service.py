import json
import os

from django.conf import settings

from phishing.ingest import email_allowed_for_workspace, gmail_fetch_mailbox


def gmail_delegation_configured():
    path = settings.PHISHING_GMAIL_SERVICE_ACCOUNT_FILE
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    return data.get("type") == "service_account" and bool(data.get("private_key"))


def build_gmail_service(mailbox):
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    credentials = service_account.Credentials.from_service_account_file(
        settings.PHISHING_GMAIL_SERVICE_ACCOUNT_FILE,
        scopes=settings.PHISHING_GMAIL_DELEGATION_SCOPES,
    )
    delegated = credentials.with_subject(mailbox)
    return build("gmail", "v1", credentials=delegated, cache_discovery=False)


def fetch_mailbox_for_report(report):
    return gmail_fetch_mailbox(report.metadata, report.reporter_email)


def mailbox_allowed(mailbox):
    return email_allowed_for_workspace(mailbox)


def fetch_raw_message(mailbox, message_id):
    import base64

    service = build_gmail_service(mailbox)
    message = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
    raw = message.get("raw") or ""
    padded = raw + "=" * (-len(raw) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    return decoded.decode("utf-8", errors="replace")
