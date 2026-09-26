#!/bin/sh
set -e

cd /app

if [ "${1:-serve}" != "serve" ]; then
  exec "$@"
fi

if [ "${CROWDPHISH_ROLE:-web}" = "web" ]; then
  python manage.py migrate --noinput
  python manage.py bootstrap
  python manage.py collectstatic --noinput
  WORKERS="${WEB_WORKERS:-2}"
  TIMEOUT="${WEB_TIMEOUT:-60}"
  RELOAD=""
  if [ "${CROWDPHISH_DEV:-0}" = "1" ]; then
    RELOAD="--reload"
  fi
  exec gunicorn crowdphish.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers "${WORKERS}" \
    --timeout "${TIMEOUT}" \
    ${RELOAD}
fi

exec python manage.py resolve_phishing_gmail_rfc822 --loop --limit "${RESOLVE_BATCH:-10}"
