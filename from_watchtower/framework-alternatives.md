# Framework alternatives

The extraction default is **monolith Django + Postgres** because the existing implementation is already Django-shaped (~58 Python modules, server-rendered templates, JSON endpoints without DRF).

## Django (recommended)

**Pros**

- Direct port of `phishing/`, `security/` subset, and templates
- ORM migrations for `PhishingReport` decoupling
- Admin for artifacts/submissions during migration
- Same auth patterns (session + API token) as Watchtower
- Gunicorn + Compose matches ops familiarity

**Cons**

- Heavier image than FastAPI
- Carries template/static conventions from Watchtower unless trimmed

**Effort:** Medium — mostly model/auth rewiring, not algorithm rewrites.

## FastAPI + SQLAlchemy

**Pros**

- Smaller runtime; async Gmail fetch theoretically nice
- OpenAPI for add-on APIs for free

**Cons**

- Rewrite all views, dashboard HTML (Jinja2 reimplementation), and ~60 modules of business logic
- Duplicate ORM models and migration story
- Bad Actor and mail assembly deeply tied to Django ORM queries

**Effort:** High — treat as greenfield rewrite.

## Node (Express/Nest) + TypeScript

**Pros**

- Single language if front-end team prefers React SPA

**Cons**

- No code reuse from Python parse/risk/cluster pipeline
- Highest regression risk for MIME parsing and Gmail edge cases

**Effort:** Very high.

## Hybrid (Django UI + FastAPI API sidecar)

**Pros**

- Theoretically isolate add-on traffic

**Cons**

- Two deployables, shared DB coupling, duplicated auth
- Add-on APIs are already thin (`gmail_report_api.py`); split adds little

**Effort:** Medium-high with operational overhead.

**Verdict:** Unnecessary unless scale demands separate API tier.

## Recommendation

1. **Phase 1:** Django monolith in new repo, Postgres, optional Celery worker, optional `ai_broker` container copy.
2. **Phase 2:** Optimize hot paths (materialized campaigns, clustering cache) inside Django.
3. Revisit FastAPI only if district standardizes on non-Django ops — not for initial extraction.

## API layer note

Current JSON endpoints use plain `JsonResponse` and `@csrf_exempt`. **Django REST Framework is optional** — adding DRF does not simplify migration unless building a public OpenAPI contract for third parties.

## Frontend note

Dashboard is server-rendered Bootstrap templates. A future React SPA would be a separate project; extraction docs assume **port templates** first for fastest parity.
