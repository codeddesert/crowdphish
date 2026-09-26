from django.conf import settings


def reef(request):
    return {
        "is_analyst": user_is_analyst(request.user),
        "forward_address": settings.PHISHING_GMAIL_GROUP_FORWARD_ADDRESS,
    }


def user_is_analyst(user):
    if not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name=settings.PHISHING_STAFF_GROUP).exists()
