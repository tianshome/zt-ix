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

PostgreSQL is exposed on host port `5433` to avoid conflicts with existing services on `5432`.

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
