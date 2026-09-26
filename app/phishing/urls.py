from django.urls import path

from phishing import views

app_name = "phishing"

urlpatterns = [
    path("", views.phishing_dashboard, name="dashboard"),
    path("incidents/<int:report_id>/", views.phishing_incident_detail, name="incident"),
    path("incidents/<int:report_id>/verdict/", views.phishing_incident_set_verdict, name="verdict"),
    path("incidents/<int:report_id>/bad-actor/match/", views.phishing_bad_actor_match, name="bad-actor-match"),
    path("incidents/<int:report_id>/bad-actor/associate/", views.phishing_bad_actor_associate, name="bad-actor-associate"),
    path("incidents/<int:report_id>/bad-actor/create/", views.phishing_bad_actor_create, name="bad-actor-create"),
    path("incidents/<int:report_id>/review-urls/analyze/", views.phishing_review_urls, name="review-urls"),
    path("incidents/<int:report_id>/review-emails/analyze/", views.phishing_review_emails, name="review-emails"),
    path("incidents/<int:report_id>/url-screenshot/", views.phishing_url_screenshot, name="url-screenshot"),
    path("incidents/<int:report_id>/reporter-ai-guidance/run/", views.phishing_reporter_ai, name="reporter-ai"),
]
