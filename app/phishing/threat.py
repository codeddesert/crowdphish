from django.conf import settings

from phishing.constants import BENIGN_VERDICTS, INCIDENT_VERDICTS, VERDICT_LEGITIMATE, VERDICT_MALWARE, VERDICT_PHISHING, VERDICT_SPAM


def threat_level(score):
    if score >= 75:
        return "high"
    if score >= settings.PHISHING_INCIDENT_ELEVATED_SCORE:
        return "elevated"
    if score >= 25:
        return "moderate"
    return "low"


def display_threat(submission):
    verdict = submission.analyst_verdict or "unknown"
    score = submission.risk_score or 0
    if verdict == VERDICT_LEGITIMATE:
        score = min(score, 10)
    elif verdict == VERDICT_SPAM:
        score = max(min(score, 45), 30)
    elif verdict == VERDICT_PHISHING:
        score = max(score, 80)
    elif verdict == VERDICT_MALWARE:
        score = max(score, 90)
    return score, threat_level(score)


def is_phishing_incident(submission):
    verdict = submission.analyst_verdict or "unknown"
    if verdict == VERDICT_LEGITIMATE:
        return False
    if verdict in INCIDENT_VERDICTS:
        return True
    if verdict in BENIGN_VERDICTS:
        return False
    return (submission.risk_score or 0) >= settings.PHISHING_INCIDENT_ELEVATED_SCORE


def fish_for_submission(submission):
    if is_phishing_incident(submission):
        return "angler"
    return "dory"
