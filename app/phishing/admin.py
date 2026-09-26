from django.contrib import admin

from phishing.models import (
    ApiClient,
    BadActorArtifact,
    BadActorProfile,
    BadActorReportLink,
    IntelScan,
    PhishingCampaignContribution,
    PhishingExtractedArtifact,
    PhishingReport,
    PhishingSubmission,
)


class ArtifactInline(admin.TabularInline):
    model = PhishingExtractedArtifact
    extra = 0


class SubmissionInline(admin.StackedInline):
    model = PhishingSubmission
    extra = 0
    can_delete = False


@admin.register(PhishingReport)
class PhishingReportAdmin(admin.ModelAdmin):
    list_display = ("id", "message_title", "reporter_email", "origin_sender", "rfc822_fetch_status", "reported_at")
    search_fields = ("message_title", "reporter_email", "gmail_message_id", "rfc822_message_id", "origin_sender")
    list_filter = ("rfc822_fetch_status", "webhook_origin")
    inlines = [SubmissionInline]


@admin.register(PhishingSubmission)
class PhishingSubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "report", "risk_score", "analyst_verdict", "analyst_confidence")
    list_filter = ("analyst_verdict",)
    inlines = [ArtifactInline]


@admin.register(PhishingCampaignContribution)
class ContributionAdmin(admin.ModelAdmin):
    list_display = ("campaign_report", "reporter_email", "vote", "updated_at")


@admin.register(ApiClient)
class ApiClientAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "gmail_report_api", "created_at")
    exclude = ()


@admin.register(BadActorProfile)
class BadActorAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at")


admin.site.register(BadActorArtifact)
admin.site.register(BadActorReportLink)
admin.site.register(IntelScan)
