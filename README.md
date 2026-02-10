# ZT Internet Exchange

ZT-IX control plane for virtual Internet Exchange onboarding with PeeringDB identity and owned self-hosted ZeroTier controller lifecycle operations.

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

### Configuration split
- `.env.example` contains secrets and runtime wiring values.
- `runtime-config.example.yaml` contains non-secret runtime defaults and policy-style settings.
- Release profile expectation: `ZT_PROVIDER=self_hosted_controller`.
- `ZT_PROVIDER=central` remains compatibility-only for migration/testing and is not a release gate.

### Self-hosted controller lifecycle scope
- Required for release: controller readiness/bootstrap checks, managed-network reconciliation, token lifecycle controls, and backup/restore validation workflows.
- Current implementation status is tracked in `IMPLEMENTATION_PLAN.md` (Sub-phase 5D).

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
   - Set OAuth signing algorithm to `RSA with SHA-2 256` (RS256) in PeeringDB app registration.
2. Set runtime variables in `.env`:
   - `PEERINGDB_CLIENT_ID`
   - `PEERINGDB_CLIENT_SECRET`
   - `PEERINGDB_REDIRECT_URI`
   - `APP_SECRET_KEY`
   - Keep `peeringdb.scopes` in your runtime YAML profile including `openid` for nonce-validated OIDC callbacks.
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

## Route Server Setup (Sub-phase 5B)

Sub-phase 5B writes deterministic per-request BIRD peer snippets to every host listed in
`route_servers.hosts` over SSH. Repeat the steps below for each route server in that list.

### 1) Controller-side runtime config profile
Keep route-server non-secret settings in a runtime config profile (example below and
in `runtime-config.example.yaml`), then map them to environment variables in your
deployment workflow.

```yaml
route_servers:
  hosts: [rs1.example.net, rs2.example.net]
  ssh:
    user: ztixsync
    port: 22
    private_key_path: /etc/zt-ix/keys/route_server_ed25519
    connect_timeout_seconds: 10.0
    strict_host_key: true
    known_hosts_file: /etc/zt-ix/known_hosts
  remote_config_dir: /etc/bird/ztix-peers.d
  local_asn: 65000
```

### 2) Packages to install on each router
Ubuntu/Debian example:

```bash
sudo apt-get update
sudo apt-get install -y bird3 openssh-server cron ca-certificates curl
```

Optional (for local RPKI validator/runtime):

```bash
sudo apt-get install -y routinator
```

### 3) Prepare SSH + config destination on each router
Create a restricted sync user and target directory:

```bash
sudo useradd --create-home --shell /bin/bash ztixsync
sudo install -o ztixsync -g ztixsync -m 750 -d /etc/bird/ztix-peers.d
sudo install -o ztixsync -g ztixsync -m 700 -d /home/ztixsync/.ssh
```

Add the controller public key to `/home/ztixsync/.ssh/authorized_keys`, then ensure
`route_servers.ssh.user` and `route_servers.ssh.private_key_path` match.

### 4) Include generated snippets from `bird.conf`
In each router’s `/etc/bird/bird.conf`, add include lines for generated peers and ROA tables:

```bird
router id 192.0.2.1;
roa4 table ztix_roa_v4;
roa6 table ztix_roa_v6;

include "/etc/bird/ztix-peers.d/*.conf";
```

### 5) RPKI refresh cron job example
If you run cron-driven ROA refresh, add a root cron entry to keep validator data current.
Example (`/etc/cron.d/ztix-rpki-refresh`):

```cron
*/15 * * * * root routinator update >/var/log/ztix-rpki-update.log 2>&1
```

If you use a different validator workflow, keep ROA tables (`ztix_roa_v4` and `ztix_roa_v6`)
fresh on the same cadence and run a config check before applying BIRD changes.

### 6) Local syntax validation before apply
On the route server, validate config syntax before any apply step:

```bash
bird -p -c /etc/bird/bird.conf
```
