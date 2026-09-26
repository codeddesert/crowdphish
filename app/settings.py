import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent

TESTING = "test" in sys.argv

SECRET_KEY = os.environ.get("SECRET_KEY") or "insecure-dev-key"
DEBUG = os.environ.get("DEBUG", "0").strip().lower() in {"1", "true", "yes"}

if TESTING:
    ALLOWED_HOSTS = ["*"]
else:
    ALLOWED_HOSTS = [
        host.strip()
        for host in os.environ.get(
            "ALLOWED_HOSTS",
            "crowdphish.washk12.org,phishing.washk12.org,localhost,crowdphish",
        ).split(",")
        if host.strip()
    ]

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CSRF_TRUSTED_ORIGINS",
        "https://crowdphish.washk12.org,https://phishing.washk12.org",
    ).split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "phishing",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "urls"
WSGI_APPLICATION = "wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "phishing.context.reef",
            ],
        },
    }
]


def _database_from_url(url):
    parsed = urlparse(url)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/"),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname or "",
        "PORT": str(parsed.port or 5432),
        "CONN_MAX_AGE": 60,
    }


if TESTING:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
else:
    database_url = os.environ.get("DATABASE_URL", "")
    if database_url.startswith("postgres"):
        DATABASES = {"default": _database_from_url(database_url)}
    else:
        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": BASE_DIR / "db.sqlite3",
            }
        }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("TIME_ZONE", "America/Denver")
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
# collectstatic output stays outside the source tree.
STATIC_ROOT = Path(os.environ.get("STATIC_ROOT", "/var/cache/crowdphish/static"))

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/phishing/"
LOGOUT_REDIRECT_URL = "/"

SESSION_COOKIE_NAME = "crowdphish_session"
CSRF_COOKIE_NAME = "crowdphish_csrftoken"
SESSION_COOKIE_SECURE = not DEBUG and not TESTING
CSRF_COOKIE_SECURE = not DEBUG and not TESTING
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

DATA_UPLOAD_MAX_MEMORY_SIZE = 12 * 1024 * 1024

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

PHISHING_STAFF_GROUP = "phishing_staff"
PHISHING_GMAIL_SERVICE_ACCOUNT_FILE = os.environ.get(
    "PHISHING_GMAIL_SERVICE_ACCOUNT_FILE", "/opt/secrets/phishing-gmail.json"
)
PHISHING_GMAIL_GROUP_INGEST_MAILBOX = os.environ.get(
    "PHISHING_GMAIL_GROUP_INGEST_MAILBOX", "watchtowerapi@washk12.org"
)
PHISHING_GMAIL_GROUP_FORWARD_ADDRESS = os.environ.get(
    "PHISHING_GMAIL_GROUP_FORWARD_ADDRESS", "phishing@washk12.org"
)
PHISHING_GMAIL_ORIGINAL_SEARCH_WINDOW_HOURS = int(
    os.environ.get("PHISHING_GMAIL_ORIGINAL_SEARCH_WINDOW_HOURS", "2")
)
PHISHING_GMAIL_DELEGATION_SCOPES = [
    scope.strip()
    for scope in os.environ.get(
        "PHISHING_GMAIL_DELEGATION_SCOPES",
        "https://www.googleapis.com/auth/gmail.modify",
    ).split(",")
    if scope.strip()
]
PHISHING_DELEGATION_ALLOWED_DOMAINS = [
    domain.strip().lower()
    for domain in os.environ.get("PHISHING_DELEGATION_ALLOWED_DOMAINS", "washk12.org").split(",")
    if domain.strip()
]
PHISHING_TRUSTED_DOMAINS = [
    domain.strip().lower()
    for domain in os.environ.get("PHISHING_TRUSTED_DOMAINS", "washk12.org").split(",")
    if domain.strip()
]

PHISHING_MAIL_CLUSTER_SOURCE_CAP = int(os.environ.get("PHISHING_MAIL_CLUSTER_SOURCE_CAP", "4000"))
PHISHING_SUBJECT_CLUSTER_MIN_RATIO = float(os.environ.get("PHISHING_SUBJECT_CLUSTER_MIN_RATIO", "0.9"))
PHISHING_SUBJECT_GROUP_MAX_SPAN_HOURS = int(os.environ.get("PHISHING_SUBJECT_GROUP_MAX_SPAN_HOURS", "24"))
PHISHING_LIST_DEFAULT_DAYS = int(os.environ.get("PHISHING_LIST_DEFAULT_DAYS", "3"))
PHISHING_LIST_PAGE_SIZE = int(os.environ.get("PHISHING_LIST_PAGE_SIZE", "50"))
PHISHING_INCIDENT_ELEVATED_SCORE = int(os.environ.get("PHISHING_INCIDENT_ELEVATED_SCORE", "50"))
PHISHING_LATEST_INCIDENT_SCAN_MAX = int(os.environ.get("PHISHING_LATEST_INCIDENT_SCAN_MAX", "100"))

IPQUALITYSCORE_API_KEY = os.environ.get("IPQUALITYSCORE_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
APIFLASH_API_KEY = os.environ.get("APIFLASH_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
AI_SERVICE_URL = os.environ.get("AI_SERVICE_URL", "")
AI_SERVICE_GEMINI_PATH = os.environ.get("AI_SERVICE_GEMINI_PATH", "/api/gemini")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "phishing": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
