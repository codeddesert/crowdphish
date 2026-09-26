from datetime import timedelta

from django.utils import timezone

from phishing.campaigns import cards_since
from phishing.threat import display_threat

TITLES = {
    "phishing": "Reported phishing",
    "malware": "Reported malware",
    "spam": "Reported spam",
    "legitimate": "Marked legitimate",
    "unknown": "Already reported",
}


def campaign_report_count(report, hours=168):
    since = timezone.now() - timedelta(hours=hours)
    for card in cards_since(since):
        if report.id in card["member_ids"]:
            return card["report_count"]
    return 1


def summarize_phishing_report_analysis(report):
    submission = report.submission
    score, level = display_threat(submission)
    verdict = submission.analyst_verdict or "unknown"
    count = campaign_report_count(report)
    times = "time" if count == 1 else "times"
    summary = (
        f"Already reported. Analyst verdict: {verdict}. "
        f"Threat score {score} ({level}). "
        f"This campaign has been reported {count} {times}."
    )
    display = {
        "title": TITLES.get(verdict, "Already reported"),
        "subtitle": f"Threat {score} · {level}",
        "detail": summary,
        "notification_text": summary,
    }
    return {
        "summary": summary,
        "verdict": verdict,
        "threat_score": score,
        "threat_level": level,
        "report_count": count,
        "display": display,
    }


CREATED_DISPLAY = {
    "title": "Report Received",
    "subtitle": "Queued for Analysis",
    "detail": "The message id is recorded. Crowdphish will fetch the mail and score it.",
    "notification_text": "Report received and queued for analysis.",
}
