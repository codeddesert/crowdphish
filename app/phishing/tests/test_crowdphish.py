import json
from datetime import timedelta

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.utils import timezone

from phishing.models import ApiClient, PhishingReport, PhishingSubmission
from phishing.parse import assemble_parsed_email, parse_mime
from phishing.risk import compute_risk
from phishing.textutil import hash_token


TOKEN = "addon-test-token"


def make_report(**kwargs):
    report = PhishingReport.objects.create(
        message_title=kwargs.get("title", "Payroll update"),
        gmail_message_id=kwargs["gmail"],
        origin_sender=kwargs.get("sender", "pay@evil.test"),
        rfc822_message_id=kwargs.get("rfc", ""),
        reporter_email=kwargs.get("reporter", "staff@washk12.org"),
        reported_at=kwargs.get("when") or timezone.now(),
        metadata={},
    )
    PhishingSubmission.objects.create(
        report=report,
        risk_score=kwargs.get("score", 10),
        analyst_verdict=kwargs.get("verdict", "unknown"),
        parsed_email={
            "schema_version": 1,
            "envelope": {"subject": kwargs.get("subject", report.message_title), "from": report.origin_sender},
            "content": {"text": kwargs.get("text", "")},
            "artifacts": [],
        },
    )
    return report


class ApiTests(TestCase):
    def setUp(self):
        ApiClient.objects.create(name="addon", token_hash=hash_token(TOKEN), gmail_report_api=True)

    def post(self, payload, token=TOKEN):
        return self.client.post(
            "/api/phishing/gmail-report/",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def test_requires_token(self):
        response = self.client.post(
            "/api/phishing/gmail-report/",
            data=json.dumps({"messageId": "abc"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_create_and_duplicate(self):
        created = self.post({"messageId": "19abc", "reporter": "staff@washk12.org", "session": "hidden"})
        self.assertEqual(created.status_code, 200)
        body = created.json()
        self.assertEqual(body["status"], "created")
        self.assertEqual(body["communication_id"], body["report_id"])
        self.assertEqual(body["display"]["title"], "Report Received")
        report = PhishingReport.objects.get(gmail_message_id="19abc")
        self.assertNotIn("session", json.dumps(report.metadata.get("original_payload")))
        self.assertEqual(report.submission.artifacts.filter(role="gmail_internal").count(), 1)

        again = self.post({"messageId": "19abc", "reporter": "staff@washk12.org"})
        self.assertEqual(again.json()["status"], "duplicate")
        self.assertEqual(again.json()["duplicate_ignored"], True)
        self.assertEqual(PhishingReport.objects.count(), 1)
        self.assertIn("analysis", again.json())

    def test_group_ingest_requires_mailbox(self):
        response = self.post({"messageId": "19group", "reportSource": "phishing_group", "reporter": "a@washk12.org"})
        self.assertEqual(response.status_code, 400)

    def test_campaigns_and_feedback(self):
        report = make_report(gmail="19camp", subject="Payroll update", rfc="<inner@evil.test>")
        listed = self.client.get(
            "/api/phishing/reported-campaigns/?hours=24",
            HTTP_AUTHORIZATION=f"Bearer {TOKEN}",
        )
        self.assertEqual(listed.status_code, 200)
        campaigns = listed.json()["campaigns"]
        self.assertEqual(campaigns[0]["communication_id"], report.id)
        self.assertEqual(campaigns[0]["report_count"], 1)

        feedback = self.client.post(
            "/api/phishing/campaign-feedback/",
            data=json.dumps(
                {
                    "campaignCommunicationId": report.id,
                    "vote": "agree",
                    "reporter": "user@washk12.org",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {TOKEN}",
        )
        self.assertEqual(feedback.status_code, 200)
        self.assertTrue(feedback.json()["created"])
        self.assertEqual(feedback.json()["vote"], "agree")

    def test_forbidden_client(self):
        ApiClient.objects.create(name="blocked", token_hash=hash_token("nope"), gmail_report_api=False)
        response = self.post({"messageId": "19no"}, token="nope")
        self.assertEqual(response.status_code, 403)


class PipelineTests(TestCase):
    def test_forward_parse_and_risk(self):
        raw = """From: Wrapper <w@washk12.org>
Subject: FW: Payroll update
Message-ID: <wrapper@washk12.org>
Content-Type: text/plain; charset=utf-8

---------- Forwarded message ---------
From: Payroll <pay@evil.test>
Subject: Payroll update
Message-ID: <inner@evil.test>

Please verify your account at https://bit.ly/pay
"""
        reported, original = parse_mime(raw)
        self.assertIsNotNone(original)
        parsed = assemble_parsed_email(gmail_message_id="19abc", reported=reported, original=original)
        self.assertEqual(parsed["envelope"]["subject"], "Payroll update")
        score, flags = compute_risk(parsed)
        self.assertGreaterEqual(score, 50)
        self.assertIn("url_shortener", [item["code"] for item in flags])

    def test_subject_cluster_and_rfc822_merge(self):
        from phishing.campaigns import cards_from_reports

        now = timezone.now()
        first = make_report(gmail="a", subject="Payroll update", when=now - timedelta(hours=2), rfc="<same@evil.test>")
        second = make_report(
            gmail="b",
            subject="Payroll update!",
            when=now - timedelta(hours=1),
            rfc="<same@evil.test>",
        )
        third = make_report(gmail="c", subject="Unrelated lunch menu", when=now, sender="cafe@washk12.org")
        cards = cards_from_reports([first, second, third])
        grouped = {tuple(sorted(card["member_ids"])): card["report_count"] for card in cards}
        self.assertIn(tuple(sorted([first.id, second.id])), grouped)
        self.assertEqual(grouped[tuple(sorted([first.id, second.id]))], 2)
        self.assertTrue(any(card["report_count"] == 1 and third.id in card["member_ids"] for card in cards))

    def test_dashboard_requires_analyst(self):
        response = self.client.get("/phishing/")
        self.assertEqual(response.status_code, 302)
        user = User.objects.create_user("analyst", password="long-test-password")
        user.groups.add(Group.objects.create(name="phishing_staff"))
        self.client.login(username="analyst", password="long-test-password")
        page = self.client.get("/phishing/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Reported campaigns")
