# Technical Stack
Version: 0.8
Date: 2026-02-12

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
4. Python stdlib `hashlib`/`hmac` for local credential hashing and constant-time verification (Auth Option A)

## 4. Data Layer
1. SQLAlchemy 2.0.37
2. Alembic 1.14.0
3. psycopg[binary] 3.2.3
4. PostgreSQL 16.6

## 5. Background Processing
1. Celery 5.4.0
2. Redis 7.4.1

## 6. Frontend Delivery
1. React `19.2.4`
2. React DOM `19.2.4`
3. TypeScript `5.9.3`
4. Vite `7.3.1`
5. shadcn-ui CLI `3.8.4`
6. npm `11.10.0`
7. i18next `24.2.1`
8. react-i18next `15.4.0`
9. Production frontend runtime: NGINX web container serving SPA static assets and proxying API requests to FastAPI container.

## 7. Security and Config
1. python-dotenv 1.0.1
2. cryptography 44.0.0
3. PyYAML 6.0.2

## 8. Testing and Quality
1. pytest 8.3.4
2. pytest-asyncio 0.25.0
3. ruff 0.8.6
4. mypy 1.14.1

## 9. Packaging and Tooling
1. uv 0.5.20
2. Docker Engine 27.4.1
3. Docker Compose v2.32.1
4. OpenSSH client (`ssh`) for route-server fanout workflows
5. BIRD 3.x for route-server config syntax validation and runtime
6. ZeroTier One service/controller runtime (owned self-hosted controller lifecycle path via local controller API)
7. NGINX container runtime for SPA delivery in production compose profile

## 9.1 Local Development Dependency Profile
1. Selected profile: infrastructure-only containers.
2. Docker Compose is used for stateful dependencies only:
   - PostgreSQL 16.6
   - Redis 7.4.1
   - ZeroTier controller runtime for lifecycle validation: `zerotier/zerotier:1.14.2`
3. Application processes run directly with `uv run` (API server, worker, and tests), not inside Docker by default.
4. Full-container application runtime is reserved for parity checks and release validation, not the default inner-loop workflow.
5. Frontend development runs with Vite dev server and proxy-to-backend API routes (`localhost:8000`).
6. Frontend compile supports a branding configuration file (Vite build input) for environment-specific app identity fields.

## 10. External Integrations (Authoritative Endpoints and Auth)
1. PeeringDB OAuth2 endpoints:
   - Authorization endpoint: `https://auth.peeringdb.com/oauth2/authorize/`
   - Token endpoint: `https://auth.peeringdb.com/oauth2/token/`
   - Profile endpoint (claims + network context): `https://auth.peeringdb.com/profile/v1`
2. PeeringDB OAuth scopes used by this app are from documented scope names:
   - `openid`
   - `profile`
   - `email`
   - `networks`
3. PeeringDB REST data API base URL: `https://www.peeringdb.com/api/`
4. ZeroTier self-hosted controller API (required release path):
   - Base URL: `http://127.0.0.1:9993/controller`
   - Auth header: `X-ZT1-Auth: <token>`
5. ZeroTier Central API (compatibility-only migration/testing path):
   - Base URL: `https://api.zerotier.com/api/v1`
   - Auth header format: `Authorization: token <token>`
6. Provisioning mode is configuration-driven:
   - `ZT_PROVIDER=central|self_hosted_controller`
   - Release expectation: `ZT_PROVIDER=self_hosted_controller`
7. Authentication mode support:
   - Auth Option A: local DB-backed username/password credentials + server CLI account provisioning
   - Auth Option B: PeeringDB OAuth/OIDC

## 11. External API Constraints
1. ZeroTier Central API rate limits are plan-dependent; provisioning worker must handle HTTP `429` with bounded retries and backoff.
2. PeeringDB OAuth scopes and profile payload shape are treated as external contracts and must be validated in integration tests.
3. PeeringDB OAuth app registration must use signing algorithm `RSA with SHA-2 256` (RS256) for the OIDC callback flow validated by this project.
4. Provider-specific behavior differences are isolated behind the contract defined in `BACKEND_STRUCTURE.md`.
5. Local auth is first-party only and must enforce normalized usernames, deterministic failures, and non-plaintext password storage.
6. Owned self-hosted controller lifecycle paths must fail closed when controller readiness/auth checks fail.
7. Release profiles must not require ZeroTier Central credentials; `ZT_CENTRAL_API_TOKEN` is compatibility-only.

## 12. Version Pinning Policy
1. All Python dependencies must be pinned in `pyproject.toml` and lockfile (`uv.lock`) to exact versions above.
2. Container image tags must use fixed versions, not `latest`.
3. Frontend dependencies must be pinned in `package-lock.json` with exact versions above once frontend implementation begins.
4. Any version change requires updating this file and changelog entry.

## 13. Source References (Official Docs)
1. PeeringDB OAuth docs: `https://docs.peeringdb.com/oauth/`
2. PeeringDB API auth docs: `https://docs.peeringdb.com/howto/authenticate/`
3. ZeroTier Central API docs: `https://docs.zerotier.com/api/central/v1/`
4. ZeroTier service/local controller API docs: `https://docs.zerotier.com/api/service/v1/`
