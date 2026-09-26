import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

from phishing.models import ApiClient
from phishing.textutil import hash_token


class Command(BaseCommand):
    help = "Create the analyst group, optional superuser, and optional API client."

    def handle(self, *args, **options):
        group, _created = Group.objects.get_or_create(name=settings.PHISHING_STAFF_GROUP)
        username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "").strip()
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")
        email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "").strip()
        if username and password:
            User = get_user_model()
            user, created = User.objects.get_or_create(username=username, defaults={"email": email, "is_staff": True, "is_superuser": True})
            if created:
                user.set_password(password)
                user.save()
                self.stdout.write(self.style.SUCCESS(f"Created analyst user {username}"))
            user.groups.add(group)
        token = os.environ.get("PHISHING_API_TOKEN", "").strip()
        name = os.environ.get("PHISHING_API_CLIENT_NAME", "gmail-addon").strip() or "gmail-addon"
        if token:
            digest = hash_token(token)
            _client, created = ApiClient.objects.get_or_create(
                token_hash=digest,
                defaults={"name": name, "gmail_report_api": True, "is_active": True},
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created API client {name}"))
