from django.db import transaction

from phishing.models import BadActorArtifact, BadActorProfile, BadActorReportLink


def candidates_for_report(report):
    keys = list(report.submission.artifacts.exclude(lookup_key="").values_list("lookup_key", flat=True))
    if not keys:
        return BadActorProfile.objects.none()
    return BadActorProfile.objects.filter(artifacts__lookup_key__in=keys).distinct()


def link_profile(profile, report):
    link, created = BadActorReportLink.objects.get_or_create(profile=profile, report=report)
    return link, created


@transaction.atomic
def create_profile_from_report(report, name="", notes=""):
    profile = BadActorProfile.objects.create(
        name=(name or report.origin_sender or f"Report {report.id}")[:200],
        notes=notes or "",
    )
    for artifact in report.submission.artifacts.exclude(artifact_type="msg_id"):
        BadActorArtifact.objects.create(
            profile=profile,
            artifact_type=artifact.artifact_type,
            lookup_key=artifact.lookup_key,
            value=artifact.value,
        )
    link_profile(profile, report)
    return profile
