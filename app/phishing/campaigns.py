from datetime import timedelta

from django.conf import settings
from django.db.models import Count
from django.utils import timezone

from phishing.models import PhishingCampaignContribution, PhishingReport
from phishing.textutil import normalize_rfc822, normalize_subject
from phishing.threat import display_threat, is_phishing_incident, scene_image


def subject_for_report(report):
    envelope = (report.submission.parsed_email or {}).get("envelope") or {}
    subject = (envelope.get("subject") or "").strip()
    if subject:
        return normalize_subject(subject)
    title = report.message_title or ""
    lowered = title.lower()
    if lowered.startswith("message ") and lowered.endswith(" reported"):
        return ""
    return normalize_subject(title)


def _ratio(left, right):
    if not left or not right:
        return 0.0
    from difflib import SequenceMatcher

    return SequenceMatcher(None, left, right).ratio()


def _span_hours(members, report):
    times = [item.reported_at for item in members] + [report.reported_at]
    return (max(times) - min(times)).total_seconds() / 3600


class _Cluster:
    def __init__(self, report, subject):
        self.members = [report]
        self.subject = subject
        self.rfc_keys = set()
        self.senders = set()
        self._absorb(report, subject)

    def _absorb(self, report, subject):
        if report.rfc822_message_id:
            self.rfc_keys.add(normalize_rfc822(report.rfc822_message_id))
        if report.origin_sender:
            self.senders.add(report.origin_sender.lower())
        if subject and not self.subject:
            self.subject = subject

    def add(self, report, subject):
        self.members.append(report)
        self._absorb(report, subject)


def cluster_reports(reports):
    ordered = sorted(reports, key=lambda item: item.reported_at)
    clusters = []
    min_ratio = settings.PHISHING_SUBJECT_CLUSTER_MIN_RATIO
    max_span = settings.PHISHING_SUBJECT_GROUP_MAX_SPAN_HOURS
    for report in ordered:
        subject = subject_for_report(report)
        placed = False
        for cluster in clusters:
            if _span_hours(cluster.members, report) > max_span:
                continue
            if _ratio(cluster.subject, subject) >= min_ratio:
                cluster.add(report, subject)
                placed = True
                break
        if not placed:
            clusters.append(_Cluster(report, subject))
    return _merge_clusters(clusters)


def _can_merge(left, right):
    if left.rfc_keys and right.rfc_keys and left.rfc_keys.intersection(right.rfc_keys):
        return True
    if left.subject and left.subject == right.subject and left.senders.intersection(right.senders):
        return True
    return False


def _merge_clusters(clusters):
    parent = list(range(len(clusters)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for i in range(len(clusters)):
        for j in range(i + 1, len(clusters)):
            if _can_merge(clusters[i], clusters[j]):
                parent[find(i)] = find(j)
    groups = {}
    for index, cluster in enumerate(clusters):
        groups.setdefault(find(index), []).append(cluster)
    merged = []
    for group in groups.values():
        base = group[0]
        for extra in group[1:]:
            for member in extra.members:
                if member not in base.members:
                    base.add(member, extra.subject)
        merged.append(base)
    return merged


def pick_representative(members):
    def rank(report):
        submission = report.submission
        verdict = submission.analyst_verdict or "unknown"
        verdict_rank = 2 if verdict in {"phishing", "malware"} else 1 if verdict not in {"", "unknown"} else 0
        return (verdict_rank, submission.risk_score or 0, report.reported_at)

    return max(members, key=rank)


def load_reports(since, cap=None):
    cap = cap or settings.PHISHING_MAIL_CLUSTER_SOURCE_CAP
    return list(
        PhishingReport.objects.filter(reported_at__gte=since)
        .select_related("submission")
        .order_by("-reported_at")[:cap]
    )


def contribution_totals(report_ids):
    rows = (
        PhishingCampaignContribution.objects.filter(campaign_report_id__in=report_ids)
        .values("campaign_report_id", "vote")
        .annotate(total=Count("id"))
    )
    totals = {}
    for row in rows:
        bucket = totals.setdefault(row["campaign_report_id"], {"agree": 0, "disagree": 0})
        if row["vote"] in bucket:
            bucket[row["vote"]] = row["total"]
    return totals


def cards_from_reports(reports):
    cards = []
    for cluster in cluster_reports(reports):
        members = [member for member in cluster.members if hasattr(member, "submission")]
        if not members:
            continue
        representative = pick_representative(members)
        submission = representative.submission
        score, level = display_threat(submission)
        incident = is_phishing_incident(submission)
        gmail_ids = []
        rfc_keys = []
        for member in members:
            if member.gmail_message_id and member.gmail_message_id not in gmail_ids:
                gmail_ids.append(member.gmail_message_id)
            key = normalize_rfc822(member.rfc822_message_id)
            if key and key not in rfc_keys:
                rfc_keys.append(key)
        cards.append(
            {
                "report": representative,
                "report_id": representative.id,
                "communication_id": representative.id,
                "member_ids": [member.id for member in members],
                "report_count": len(members),
                "threat_score": score,
                "threat_level": level,
                "is_incident": incident,
                "scene": scene_image(
                    report_count=len(members),
                    threat_level=level,
                    is_incident=incident,
                ),
                "analyst_verdict": submission.analyst_verdict or "unknown",
                "analyst_confidence": submission.analyst_confidence or "",
                "analyst_notes": submission.analyst_notes or "",
                "analyst_verdict_at": submission.analyst_verdict_at,
                "subject": (submission.parsed_email or {}).get("envelope", {}).get("subject")
                or representative.message_title,
                "subject_normalized": cluster.subject,
                "origin_sender": representative.origin_sender,
                "rfc822_message_id": representative.rfc822_message_id,
                "rfc822_message_id_key": normalize_rfc822(representative.rfc822_message_id),
                "rfc822_message_id_keys": rfc_keys,
                "gmail_message_ids": gmail_ids,
                "origin_at": representative.reported_at,
                "reported_at": max(member.reported_at for member in members),
            }
        )
    cards.sort(key=lambda card: card["reported_at"], reverse=True)
    return cards


def cards_since(since):
    return cards_from_reports(load_reports(since))


def find_campaign_report_id(*, report_id=None, rfc822_message_id="", origin_sender="", subject="", hours=168):
    since = timezone.now() - timedelta(hours=hours)
    cards = cards_since(since)
    if report_id:
        for card in cards:
            if report_id == card["report_id"] or report_id in card["member_ids"]:
                return card["report_id"]
        if PhishingReport.objects.filter(pk=report_id).exists():
            return report_id
        return None
    rfc_key = normalize_rfc822(rfc822_message_id)
    normalized = normalize_subject(subject)
    sender = (origin_sender or "").strip().lower()
    for card in cards:
        if rfc_key and rfc_key in card["rfc822_message_id_keys"]:
            return card["report_id"]
        if sender and normalized and sender == (card["origin_sender"] or "").lower() and normalized == card["subject_normalized"]:
            return card["report_id"]
    fallback = PhishingReport.objects.filter(reported_at__gte=since)
    if rfc_key:
        match = fallback.filter(rfc822_message_id__iexact=rfc_key).order_by("-reported_at").first()
        if match:
            return match.id
    if sender and normalized:
        for report in fallback.filter(origin_sender__iexact=sender):
            if subject_for_report(report) == normalized:
                return report.id
    return None


def campaign_payload(card, contributions):
    votes = contributions.get(card["report_id"], {"agree": 0, "disagree": 0})
    return {
        "communication_id": card["communication_id"],
        "report_id": card["report_id"],
        "threat_score": card["threat_score"],
        "threat_level": card["threat_level"],
        "origin_sender": card["origin_sender"],
        "subject": card["subject"],
        "subject_normalized": card["subject_normalized"],
        "rfc822_message_id": card["rfc822_message_id"],
        "rfc822_message_id_key": card["rfc822_message_id_key"],
        "rfc822_message_id_keys": card["rfc822_message_id_keys"],
        "gmail_message_ids": card["gmail_message_ids"],
        "origin_at": card["origin_at"].isoformat() if card["origin_at"] else None,
        "match_window_hours": settings.PHISHING_GMAIL_ORIGINAL_SEARCH_WINDOW_HOURS,
        "report_count": card["report_count"],
        "analyst_verdict": card["analyst_verdict"],
        "analyst_confidence": card["analyst_confidence"],
        "analyst_notes": card["analyst_notes"],
        "analyst_verdict_at": card["analyst_verdict_at"].isoformat() if card["analyst_verdict_at"] else None,
        "contributions": votes,
    }


def reported_campaigns(hours):
    since = timezone.now() - timedelta(hours=hours)
    cards = cards_since(since)
    totals = contribution_totals([card["report_id"] for card in cards])
    return [campaign_payload(card, totals) for card in cards]


def record_contribution(*, campaign_report_id, reporter_email, vote, gmail_message_id="", metadata=None):
    contribution, created = PhishingCampaignContribution.objects.update_or_create(
        campaign_report_id=campaign_report_id,
        reporter_email=reporter_email,
        defaults={
            "vote": vote,
            "gmail_message_id": gmail_message_id or "",
            "metadata": metadata or {},
        },
    )
    return contribution, created
