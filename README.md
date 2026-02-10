# ZT Internet Exchange

ZeroTier controller for virtual Internet Exchange onboarding with PeeringDB identity.

## Phase 1 Bootstrap

### Prerequisites
- Python `3.13.x`
- `uv` package manager
- Docker Engine + Docker Compose plugin (for local PostgreSQL/Redis only)

### Local dependency profile
This repository uses the following for day-to-day development:
- Run infrastructure dependencies (PostgreSQL + Redis) with Docker Compose.
- Run application processes directly on host with `uv run` (API, worker, tests).
- Do not default to full app-in-container workflow for inner-loop development.

### Install dependencies
```bash
uv sync --dev
```

### Start local dependencies
```bash
docker compose up -d postgres redis
```

PostgreSQL is exposed on host port `5433` to avoid conflicts with existing/production services on `5432`.

### Start the API
```bash
uv run uvicorn app.main:app --reload
```

### Verification commands
```bash
uv run ruff check .
uv run mypy .
uv run pytest -q
```

## Phase 3 Auth Integration (PeeringDB)

### Automated verification in this environment
```bash
uv run pytest tests/auth -q
```

### Browser integration checks (manual, outside this environment)
Use these steps on a machine where a browser is available.

1. Register or reuse a PeeringDB OAuth application:
   - Redirect URI must exactly match `PEERINGDB_REDIRECT_URI`.
   - Example: `http://localhost:8000/auth/callback`.
2. Set runtime variables in `.env`:
   - `PEERINGDB_CLIENT_ID`
   - `PEERINGDB_CLIENT_SECRET`
   - `PEERINGDB_REDIRECT_URI`
   - `APP_SECRET_KEY`
3. Start local dependencies and apply schema:
   ```bash
   docker compose up -d postgres redis
   uv run alembic upgrade head
   ```
4. Run the API:
   ```bash
   uv run uvicorn app.main:app --reload
   ```
5. Open browser and test success path:
   - Visit `http://localhost:8000/auth/login`.
   - Complete PeeringDB login/consent.
   - Confirm redirect lands on `http://localhost:8000/onboarding`.
   - Confirm `GET http://localhost:8000/onboarding` returns authenticated payload.
6. Test callback failure paths:
   - Invalid state:
     - Run `http://localhost:8000/auth/callback?code=fake&state=bad`.
     - Expect redirect to `/error?code=invalid_state`.
   - Missing code:
     - Run `http://localhost:8000/auth/callback?state=anything`.
     - Expect redirect to `/error?code=missing_code_or_state`.
7. Test replay protection:
   - Complete one normal login flow.
   - Reuse the exact callback URL from browser history.
   - Expect redirect to `/error?code=invalid_state`.
8. Test logout:
   - Visit `http://localhost:8000/auth/logout`.
   - Then request `http://localhost:8000/onboarding`.
   - Expect `401 authentication required`.
