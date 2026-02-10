# ZT Internet Exchange

ZT-IX control plane for virtual Internet Exchange onboarding with PeeringDB identity and owned self-hosted ZeroTier controller lifecycle operations.

## Phase 1 Bootstrap

### Prerequisites
- Python `3.13.x`
- `uv` package manager
- Docker Engine + Docker Compose plugin (for local PostgreSQL/Redis and self-hosted ZeroTier controller runtime validation)

### Local dependency profile
This repository uses the following for day-to-day development:
- Run infrastructure dependencies with Docker Compose:
  - PostgreSQL + Redis for baseline API/worker workflows.
  - `zerotier-controller` when validating self-hosted provider/lifecycle behavior.
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
docker compose up -d postgres redis zerotier-controller
```

PostgreSQL is exposed on host port `5433` to avoid conflicts with existing/production services on `5432`.

### Bootstrap self-hosted controller auth token (Step 8.0)
After `zerotier-controller` starts, source the controller API token from
`/var/lib/zerotier-one/authtoken.secret` (or inject the same token from your secret manager).
The compose service uses the pinned image tag `zerotier/zerotier:1.14.2`.
The repo-managed `docker/zerotier/local.conf` sets:
- `settings.allowManagementFrom = ["0.0.0.0/0"]`
so host-side management API probes to `127.0.0.1:9993` are accepted.

```bash
export ZT_CONTROLLER_AUTH_TOKEN="$(docker compose exec -T zerotier-controller cat /var/lib/zerotier-one/authtoken.secret | tr -d '\r\n')"
```

### Validate controller API reachability
```bash
curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/status
curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/controller
curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/controller/network

docker compose exec -T zerotier-controller sh -lc \
'TOKEN="$(cat /var/lib/zerotier-one/authtoken.secret)"; \
curl -fsS -H "X-ZT1-Auth: ${TOKEN}" http://127.0.0.1:9993/status'
```

### Phase 8 lifecycle operations CLI
Use these commands for controller lifecycle ownership workflows (readiness gate, token reload, backup/restore drill):

```bash
uv run python -m app.cli.controller_lifecycle preflight
uv run python -m app.cli.controller_lifecycle reload-token --token-file /var/lib/zerotier-one/authtoken.secret
uv run python -m app.cli.controller_lifecycle backup
uv run python -m app.cli.controller_lifecycle restore-validate --backup-path /var/backups/zt-ix-controller/<backup-dir>
```

Operational notes:
- `preflight` runs readiness probes and required-network reconciliation.
- `reload-token` re-reads token material, then re-runs lifecycle preflight.
- `backup` stores `controller.d`, `identity.public`, `identity.secret`, and `authtoken.secret` under `ZT_CONTROLLER_BACKUP_DIR` with retention enforced by `ZT_CONTROLLER_BACKUP_RETENTION_COUNT`.
- `restore-validate` restores backup artifacts into `ZT_CONTROLLER_STATE_DIR` and requires readiness + reconciliation to pass before success.

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

### 7) Live integration test creates a temporary BGP session
Run the live integration test to create a temporary managed BGP protocol, verify it is
visible in BIRD, and then clean up the snippet:

```bash
ZTIX_RUN_ROUTE_SERVER_INTEGRATION=1 \
ZTIX_ROUTE_SERVER_TEST_SSH_KEY_PATH=/tmp/ztix_route_server_ed25519 \
uv run pytest tests/route_servers/test_live_integration.py -q -k live_route_server_creates_test_bgp_session
```

Notes:
- The test reads route-server host/user/port/path values from `runtime-config.yaml` by default.
- Override config path with `ZTIX_RUNTIME_CONFIG_PATH=/path/to/runtime-config.yaml` if needed.
- The test auto-runs `birdc configure check` and timed `birdc configure` during cleanup.
