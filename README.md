# ZT Internet Exchange

ZeroTier controller for virtual Internet Exchange onboarding with PeeringDB identity.

## Phase 1 Bootstrap

### Prerequisites
- Python `3.13.x`
- `uv` package manager

### Install dependencies
```bash
uv sync --dev
```

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
