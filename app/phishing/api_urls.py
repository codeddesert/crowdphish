from django.urls import path

from phishing import api

urlpatterns = [
    path("gmail-report/", api.api_phishing_gmail_report, name="gmail-report"),
    path("reported-campaigns/", api.api_phishing_reported_campaigns, name="reported-campaigns"),
    path("campaign-feedback/", api.api_phishing_campaign_feedback, name="campaign-feedback"),
]
