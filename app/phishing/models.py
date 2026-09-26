from django.conf import settings
from django.db import models

from phishing.constants import ORIGIN_GMAIL_REPORT, VERDICT_UNKNOWN, VERDICTS


class PhishingReport(models.Model):
    """One reported message. Replaces Watchtower's Communication row for phishing."""

    legacy_communication_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    webhook_origin = models.CharField(max_length=128, default=ORIGIN_GMAIL_REPORT, db_index=True)
    message_title = models.CharField(max_length=500, blank=True)
    message_body = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    reporter_email = models.CharField(max_length=254, blank=True)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="phishing_reports",
    )
    gmail_message_id = models.CharField(max_length=128, blank=True, db_index=True)
    rfc822_message_id = models.CharField(max_length=512, blank=True, db_index=True)
    origin_sender = models.CharField(max_length=254, blank=True, db_index=True)
    conversation_key = models.CharField(max_length=180, blank=True, db_index=True)
    rfc822_fetch_status = models.CharField(max_length=32, blank=True, db_index=True)
    reported_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-reported_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["webhook_origin", "gmail_message_id"],
                condition=models.Q(gmail_message_id__gt=""),
                name="uniq_phish_gmail_message",
            )
        ]
        indexes = [
            models.Index(fields=["webhook_origin", "-reported_at"]),
        ]

    def __str__(self):
        return self.message_title or f"Report {self.pk}"


class PhishingSubmission(models.Model):
    report = models.OneToOneField(PhishingReport, on_delete=models.CASCADE, related_name="submission")
    parsed_email = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_flags = models.JSONField(default=list, blank=True)
    cluster_canonical = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="cluster_peers",
    )
    analyst_verdict = models.CharField(max_length=32, default=VERDICT_UNKNOWN, choices=[(v, v) for v in VERDICTS])
    analyst_confidence = models.CharField(max_length=16, blank=True)
    analyst_notes = models.TextField(blank=True)
    analyst_verdict_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="phishing_verdicts",
    )
    analyst_verdict_at = models.DateTimeField(null=True, blank=True)
    reporter_ai_guidance_json = models.JSONField(default=dict, blank=True)
    reporter_ai_internal_generated_at = models.DateTimeField(null=True, blank=True)
    reporter_ai_gemini_generated_at = models.DateTimeField(null=True, blank=True)
    reporter_ai_last_request_payload = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [models.Index(fields=["risk_score", "analyst_verdict"])]

    def __str__(self):
        return f"Submission for report {self.report_id}"


class PhishingExtractedArtifact(models.Model):
    submission = models.ForeignKey(PhishingSubmission, on_delete=models.CASCADE, related_name="artifacts")
    artifact_type = models.CharField(max_length=32)
    role = models.CharField(max_length=64, blank=True)
    value = models.TextField(blank=True)
    lookup_key = models.CharField(max_length=512)
    domain = models.CharField(max_length=255, blank=True, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["submission", "artifact_type", "lookup_key"],
                name="uniq_phish_artifact_lookup",
            )
        ]
        indexes = [models.Index(fields=["lookup_key"])]


class PhishingCampaignContribution(models.Model):
    campaign_report = models.ForeignKey(PhishingReport, on_delete=models.CASCADE, related_name="contributions")
    reporter_email = models.CharField(max_length=254)
    vote = models.CharField(max_length=16)
    gmail_message_id = models.CharField(max_length=128, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["campaign_report", "reporter_email"],
                name="uniq_phish_campaign_vote",
            )
        ]


class ApiClient(models.Model):
    name = models.CharField(max_length=120)
    token_hash = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    gmail_report_api = models.BooleanField(default=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="phishing_api_clients",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class BadActorProfile(models.Model):
    name = models.CharField(max_length=200)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class BadActorArtifact(models.Model):
    profile = models.ForeignKey(BadActorProfile, on_delete=models.CASCADE, related_name="artifacts")
    artifact_type = models.CharField(max_length=32)
    lookup_key = models.CharField(max_length=512, db_index=True)
    value = models.TextField(blank=True)


class BadActorReportLink(models.Model):
    profile = models.ForeignKey(BadActorProfile, on_delete=models.CASCADE, related_name="report_links")
    report = models.ForeignKey(PhishingReport, on_delete=models.CASCADE, related_name="bad_actor_links")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["profile", "report"], name="uniq_bad_actor_report")
        ]


class IntelScan(models.Model):
    submission = models.ForeignKey(PhishingSubmission, on_delete=models.CASCADE, related_name="intel_scans")
    kind = models.CharField(max_length=32)
    provider = models.CharField(max_length=32)
    lookup_key = models.CharField(max_length=512, db_index=True)
    result = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
