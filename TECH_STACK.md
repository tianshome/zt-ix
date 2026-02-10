# Technical Stack
Version: 0.1
Date: 2026-02-10

Related docs: `PRD.md`, `BACKEND_STRUCTURE.md`, `IMPLEMENTATION_PLAN.md`

## 1. Runtime and Language
1. Python 3.13.1

## 2. Backend Framework
1. FastAPI 0.115.6
2. Uvicorn 0.34.0
3. Pydantic 2.10.4

## 3. Auth and HTTP
1. Authlib 1.3.2
2. httpx 0.28.1
3. itsdangerous 2.2.0

## 4. Data Layer
1. SQLAlchemy 2.0.37
2. Alembic 1.14.0
3. psycopg[binary] 3.2.3
4. PostgreSQL 16.6

## 5. Background Processing
1. Celery 5.4.0
2. Redis 7.4.1

## 6. Frontend Delivery
1. Jinja2 3.1.5
2. HTMX 1.9.12
3. Alpine.js 3.14.1

## 7. Security and Config
1. python-dotenv 1.0.1
2. cryptography 44.0.0

## 8. Testing and Quality
1. pytest 8.3.4
2. pytest-asyncio 0.25.0
3. ruff 0.8.6
4. mypy 1.14.1

## 9. Packaging/Tooling
1. uv 0.5.20
2. Docker Engine 27.4.1
3. Docker Compose v2.32.1

## 10. External APIs
1. PeeringDB OIDC/OAuth endpoints from `auth.peeringdb.com` and docs in `docs.peeringdb.com`.
2. PeeringDB data APIs under `https://www.peeringdb.com/api/`.
3. ZeroTier Central API v1 at `https://api.zerotier.com/api/v1` (provider mode: `central`).
4. ZeroTier local controller API at `http://127.0.0.1:9993/controller/...` using `X-ZT1-Auth` (provider mode: `self_hosted_controller`).
5. Provider mode is configuration-driven via `ZT_PROVIDER=central|self_hosted_controller`.

## 11. Version Pinning Policy
1. All Python dependencies must be pinned in `pyproject.toml` and lockfile (`uv.lock`) to exact versions above.
2. Container image tags must use fixed versions, not `latest`.
3. Any version change requires updating this file and changelog entry.
