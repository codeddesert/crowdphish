ORIGIN_GMAIL_REPORT = "Gmail_Phishing_MessageId_Report"

VERDICT_UNKNOWN = "unknown"
VERDICT_PHISHING = "phishing"
VERDICT_MALWARE = "malware"
VERDICT_SPAM = "spam"
VERDICT_LEGITIMATE = "legitimate"
VERDICTS = (
    VERDICT_UNKNOWN,
    VERDICT_PHISHING,
    VERDICT_MALWARE,
    VERDICT_SPAM,
    VERDICT_LEGITIMATE,
)
INCIDENT_VERDICTS = {VERDICT_PHISHING, VERDICT_MALWARE}
BENIGN_VERDICTS = {VERDICT_LEGITIMATE, VERDICT_SPAM}

CONFIDENCE_LEVELS = ("", "low", "medium", "high")

SECRET_PAYLOAD_KEYS = {
    "session",
    "apikey",
    "api_key",
    "sessiontoken",
    "session_token",
    "authorization",
    "password",
    "token",
    "webhook_secret",
}
