# Backend Structure
Version: 0.8
Date: 2026-02-12

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `IMPLEMENTATION_PLAN.md`

## 1. Architecture Overview
1. API server: FastAPI.
2. Relational storage: PostgreSQL.
3. Queue and worker: Celery + Redis for provisioning and reconciliation jobs.
4. External systems:
   - PeeringDB OAuth endpoints and PeeringDB REST API.
   - ZeroTier provisioning provider (`self_hosted_controller` release path; `central` compatibility-only).
5. Owned self-hosted controller lifecycle:
   - controller runtime readiness/preflight gate,
   - managed network bootstrap/reconciliation,
   - credential lifecycle and backup/restore operational workflows.
6. Authentication modes:
   - Auth Option A: local credentials stored in DB (`local_credential`) with `app_user` as canonical user profile.
   - Auth Option B: PeeringDB OAuth identities mapped onto canonical `app_user`.

## 1.1 ZeroTier Identifier Canonical Model
1. `node_id` = ZeroTier node address (40-bit, 10 lowercase hex characters).
2. `zt_network_id` = full ZeroTier network ID (64-bit, 16 lowercase hex characters).
3. `zt_network_suffix` = last 6 lowercase hex characters of the full network ID.
4. In `self_hosted_controller` mode, backend computes required full network IDs from:
   - controller prefix (first 10 hex characters) read live from controller API metadata (`GET /controller`), and
   - configured suffixes from `runtime-config.yaml`.
5. To avoid repetition/drift, runtime config must store suffixes only, not repeated full network IDs.

## 2. Core Domain Invariants
1. Canonical application user identity is `app_user.id` (UUID).
2. `app_user.peeringdb_user_id` is unique when present and nullable for local-only users.
3. Local credential usernames are unique after normalization (lowercase and trimmed).
4. A user can only create requests for ASNs currently linked to that user from either PeeringDB sync or local assignment.
5. If user-level associated-network rows exist, request target network must be within that association set.
6. Active request uniqueness is scoped by (`asn`, `zt_network_id`, `node_id`) across statuses:
   - exact duplicates for the same key are blocked in `pending`, `approved`, `provisioning`, `active`
   - different `node_id` values for the same ASN/network can coexist
   - `node_id IS NULL` is treated as its own single active slot per (`asn`, `zt_network_id`)
7. Request state transitions must follow `APP_FLOW.md`.
8. `zt_membership` is one-to-one with `join_request` and unique per (`zt_network_id`, `node_id`).
9. In self-hosted mode, provisioning must fail closed when controller lifecycle preflight is unhealthy.
10. `zt_network_id` and `node_id` values are lowercase hex only.
11. In self-hosted mode, required managed network IDs are derived from one live controller prefix source of truth plus configured suffixes.
12. Invalid/duplicate suffixes or prefix/suffix composition mismatches fail lifecycle preflight.
13. In self-hosted mode, provisioning persists one deterministic IPv6 `/128` assignment per `join_request_id` in SQL.
14. IPv6 allocation sequence is monotonic and never reused per (`zt_network_id`, `asn`), including failed/retried requests.

## 3. Database Schema (PostgreSQL)
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE app_user (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  peeringdb_user_id BIGINT UNIQUE,
  username TEXT NOT NULL,
  full_name TEXT,
  email TEXT,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE local_credential (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES app_user(id) ON DELETE CASCADE,
  login_username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (login_username = lower(login_username))
);

CREATE TABLE user_asn (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  asn BIGINT NOT NULL,
  net_id BIGINT,
  net_name TEXT,
  source TEXT NOT NULL DEFAULT 'peeringdb',
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, asn)
);

CREATE TABLE zt_network (
  id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{16}$'),
  name TEXT NOT NULL,
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_network_access (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  zt_network_id TEXT NOT NULL REFERENCES zt_network(id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT 'local',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, zt_network_id)
);

CREATE TYPE request_status AS ENUM (
  'pending',
  'approved',
  'provisioning',
  'active',
  'rejected',
  'failed'
);

CREATE TABLE join_request (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE RESTRICT,
  asn BIGINT NOT NULL,
  zt_network_id TEXT NOT NULL REFERENCES zt_network(id) ON DELETE RESTRICT,
  status request_status NOT NULL DEFAULT 'pending',
  node_id TEXT CHECK (node_id IS NULL OR node_id ~ '^[0-9a-f]{10}$'),
  notes TEXT,
  reject_reason TEXT,
  last_error TEXT,
  retry_count INT NOT NULL DEFAULT 0,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ,
  provisioned_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE zt_membership (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  join_request_id UUID NOT NULL UNIQUE REFERENCES join_request(id) ON DELETE CASCADE,
  zt_network_id TEXT NOT NULL REFERENCES zt_network(id) ON DELETE RESTRICT,
  node_id TEXT NOT NULL CHECK (node_id ~ '^[0-9a-f]{10}$'),
  member_id TEXT NOT NULL,
  is_authorized BOOLEAN NOT NULL DEFAULT FALSE,
  assigned_ips TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (zt_network_id, node_id)
);

CREATE TABLE zt_ipv6_allocation_state (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  zt_network_id TEXT NOT NULL REFERENCES zt_network(id) ON DELETE RESTRICT,
  asn BIGINT NOT NULL,
  last_sequence BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (zt_network_id, asn)
);

CREATE TABLE zt_ipv6_assignment (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  join_request_id UUID NOT NULL UNIQUE REFERENCES join_request(id) ON DELETE CASCADE,
  zt_network_id TEXT NOT NULL REFERENCES zt_network(id) ON DELETE RESTRICT,
  asn BIGINT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  assigned_ip TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (zt_network_id, asn, sequence),
  UNIQUE (zt_network_id, assigned_ip)
);

CREATE TABLE oauth_state_nonce (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  state TEXT NOT NULL UNIQUE,
  nonce TEXT NOT NULL,
  pkce_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_event (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES app_user(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_join_request_status ON join_request(status);
CREATE INDEX idx_join_request_user ON join_request(user_id);
CREATE UNIQUE INDEX uq_join_request_active_per_asn_network_with_node
  ON join_request(asn, zt_network_id, node_id)
  WHERE status IN ('pending', 'approved', 'provisioning', 'active') AND node_id IS NOT NULL;
CREATE UNIQUE INDEX uq_join_request_active_per_asn_network_without_node
  ON join_request(asn, zt_network_id)
  WHERE status IN ('pending', 'approved', 'provisioning', 'active') AND node_id IS NULL;
CREATE INDEX idx_audit_event_created_at ON audit_event(created_at);
CREATE INDEX idx_local_credential_user_id ON local_credential(user_id);
CREATE INDEX idx_user_network_access_user_id ON user_network_access(user_id);
```

## 4. Authentication and Session Contract
1. Auth Option B start endpoint (`POST /api/v1/auth/peeringdb/start`) creates OAuth authorization context (`state`, `nonce`, PKCE) and returns authorization URL payload.
2. Auth Option B callback endpoint (`POST /api/v1/auth/peeringdb/callback`) validates `state`, exchanges code for token set, and consumes one-time state row.
3. Auth Option A endpoint (`POST /api/v1/auth/local/login`) verifies username/password against `local_credential.password_hash`.
4. Logout endpoint (`POST /api/v1/auth/logout`) clears session and emits auth audit event.
5. Identity and ASN/network authorization context are loaded from:
   - PeeringDB profile/API for OAuth users.
   - persisted local assignments for local-credential users.
6. Local session cookie requirements:
   - HTTP-only
   - Secure in production
   - SameSite=Lax
7. Replay protection:
   - Callback with used or expired `state` is rejected and audited.
8. Local credential verification requirements:
   - passwords stored as salted hashes only
   - constant-time comparison for verification path
   - disabled credentials cannot establish sessions
9. Auth APIs return JSON success/error payloads for SPA handling; backend redirect/error-page responses are out of scope.

## 5. ZeroTier Provisioning Provider Contract
1. Workflow code depends on provider interface, not provider-specific endpoints.
2. Supported provider modes:
   - `self_hosted_controller`: local controller API (`X-ZT1-Auth: <token>`) (required release mode)
   - `central`: ZeroTier Central API (`Authorization: token <token>`) (compatibility-only)
3. Minimum provider interface methods:
   - `validate_network(zt_network_id) -> bool`
   - `authorize_member(zt_network_id, node_id, asn, request_id) -> ProvisionResult`
4. `ProvisionResult` normalized fields:
   - `member_id: str`
   - `is_authorized: bool`
   - `assigned_ips: list[str]`
   - `provider_name: str`
5. Idempotency rule:
   - Calling `authorize_member` repeatedly for same request/node/network must converge on one persisted membership row.

## 5.2 Self-Hosted Controller Lifecycle Ownership Contract (Sub-phase 5D)
1. Startup/worker preflight must verify controller API/auth readiness before provisioning execution.
2. Startup/worker preflight must read controller metadata (`/controller`) and capture controller prefix (first 10 hex characters).
3. Required controller-managed networks are expanded from configured suffix list to full IDs and must exist (create/reconcile) before member authorization attempts.
4. Suffix validation rules:
   - each suffix is lowercase hex and exactly 6 characters,
   - duplicate suffixes are rejected before reconciliation,
   - full IDs are not duplicated in configuration except temporary migration compatibility paths.
5. Lifecycle operations must emit audit events for success/failure:
   - readiness checks,
   - prefix read/suffix expansion outcomes,
   - credential/token lifecycle actions,
   - backup and restore validation actions.
6. Provisioning must remain blocked while lifecycle preflight is unhealthy.
7. Release readiness requires self-hosted-only operation without Central credentials.

## 5.3 Route Server Option A Contract (Sub-phase 5B)
1. After successful member authorization, worker renders deterministic BIRD peer config from:
   - request ID
   - ASN
   - node ID
   - assigned endpoint IPs from provider result
2. Generated peer config must enforce RPKI validation in import policy via ROA checks:
   - `roa_check(ztix_roa_v4, ...)`
   - `roa_check(ztix_roa_v6, ...)`
3. Generated config is fanned out over SSH to every configured route server host from runtime settings.
4. No persisted per-route-server DB model is required in Option A phase scope.
5. Route-server sync failures must be surfaced as provisioning failures with retry-safe error context.

## 6. API Contract (v1)
All API responses are JSON.

### 6.1 Success envelope
```json
{
  "data": {}
}
```

### 6.2 Error envelope
```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": {}
  }
}
```

### 6.3 Endpoints
1. `POST /api/v1/auth/peeringdb/start`
   - Auth: public.
   - `200`: OAuth start payload including authorization URL and callback correlation context.
   - `503`: auth provider unavailable.
2. `POST /api/v1/auth/peeringdb/callback`
   - Auth: public.
   - Body: `code`, `state` (and optional provider error fields if surfaced by frontend callback route).
   - `200`: session established + auth summary payload.
   - `400`: callback validation failure (`invalid_state`, `expired_state`, `invalid_nonce`, `upstream_auth_failure`).
3. `POST /api/v1/auth/local/login`
   - Auth: public.
   - Body: `username`, `password`.
   - `200`: session established + auth summary payload.
   - `401`: invalid credentials.
   - `403`: disabled credential or local auth disabled.
4. `POST /api/v1/auth/logout`
   - Auth: session required.
   - `200`: session cleared.
5. `GET /api/v1/onboarding/context`
   - Auth: user session required.
   - `200`: eligible ASN list + allowed target network list + current submission constraints.
   - `401`: unauthenticated.
6. `GET /api/v1/me`
   - Auth: user session required.
   - `200`: user profile + linked ASNs.
   - `401`: unauthenticated.
7. `GET /api/v1/asns`
   - Auth: user session required.
   - `200`: eligible ASN list.
   - `401`: unauthenticated.
8. `POST /api/v1/requests`
   - Auth: user session required.
   - Body: `asn`, `zt_network_id`, optional `node_id`, optional `notes`.
   - `201`: request created in `pending`.
   - `400`: validation error.
   - `403`: ASN not authorized for user.
   - `409`: duplicate active request for same ASN/network/`node_id` key.
9. `GET /api/v1/requests`
   - Auth: user session required.
   - `200`: user-owned request list.
10. `GET /api/v1/requests/{request_id}`
   - Auth: user session required.
   - `200`: request detail + membership if present.
   - `404`: not found or not visible to caller.
11. `GET /api/v1/admin/requests`
   - Auth: admin required.
   - Query: optional `status`, `asn`, `zt_network_id`, `min_age_minutes`.
   - `200`: admin-visible request list.
   - `403`: not admin.
12. `GET /api/v1/admin/requests/{request_id}`
   - Auth: admin required.
   - `200`: admin request detail + audit context.
   - `403`: not admin.
   - `404`: not found.
13. `POST /api/v1/admin/requests/{request_id}/approve`
   - Auth: admin required.
   - `200`: status set `approved`, job queued.
   - `403`: not admin.
   - `409`: invalid current state.
14. `POST /api/v1/admin/requests/{request_id}/reject`
   - Auth: admin required.
   - Body: `reject_reason` required.
   - `200`: status set `rejected`.
   - `400`: missing reason.
   - `403`: not admin.
   - `409`: invalid current state.
15. `POST /api/v1/admin/requests/{request_id}/retry`
   - Auth: admin required.
   - `200`: status set `approved`, job requeued.
   - `403`: not admin.
   - `409`: request is not `failed`.

## 7. Worker and Retry Contract
1. Worker only consumes requests in `approved` state.
2. Worker sets status to `provisioning` before external provider call.
3. On success:
   - upsert `zt_membership`
   - set request `active`
   - set `provisioned_at`
4. On failure:
   - set request `failed`
   - increment `retry_count`
   - persist `last_error`
5. Retry execution is explicit admin action for terminal `failed` records.
6. Automatic retries for transient network/provider failures are allowed only within one worker attempt boundary and must be bounded.
7. In `self_hosted_controller` mode, worker enforces lifecycle readiness preflight before provider calls.
8. If lifecycle readiness checks fail, request transitions to `failed` with actionable lifecycle error context.
9. In `self_hosted_controller` mode, worker allocates/reuses deterministic IPv6 before provider authorization and persists assignment state even when provisioning later fails.

## 8. Storage and Secret Rules
1. Provider secrets (Central API token or controller auth token) are never stored in plaintext DB rows.
2. Secret source is runtime environment or external secret manager.
3. `ZT_PROVIDER` selects provider mode; startup validation fails if mode is invalid or required credentials are missing.
4. OAuth transient values (`state`, `nonce`, verifier) are short-lived and purged after use or expiry.
5. PeeringDB access tokens are stored encrypted only when required for async behavior; otherwise kept in session context only.
6. Local password material is stored only as non-reversible hashes and never logged.
7. Controller lifecycle credential rotation events must be auditable and avoid plaintext secret logging.
8. Backup artifacts for controller lifecycle workflows must be access-restricted and validated before use.

## 9. Required Environment Variables
Current implementation:
1. `APP_SECRET_KEY`
2. `DATABASE_URL`
3. `REDIS_URL`
4. `PEERINGDB_CLIENT_ID`
5. `PEERINGDB_CLIENT_SECRET`
6. `PEERINGDB_REDIRECT_URI`
7. `LOCAL_AUTH_ENABLED` (`true|false`, default `true`)
8. `ZT_PROVIDER` (`central|self_hosted_controller`)
9. `ZT_CENTRAL_API_TOKEN` (required when `ZT_PROVIDER=central`)
10. `ZT_CONTROLLER_BASE_URL` (required when `ZT_PROVIDER=self_hosted_controller`)
11. `ZT_CONTROLLER_AUTH_TOKEN` (required when token-file source is unset)
12. `ZT_CONTROLLER_AUTH_TOKEN_FILE` (optional runtime secret source for controller token)
13. `ZT_CONTROLLER_REQUIRED_NETWORK_IDS` (legacy compatibility input for full 16-char IDs; planned removal after suffix-only migration)
14. `ZT_CONTROLLER_READINESS_STRICT` (`true|false`; startup fail-closed toggle)
15. `ZT_CONTROLLER_BACKUP_DIR` (backup artifact destination path)
16. `ZT_CONTROLLER_BACKUP_RETENTION_COUNT` (retention policy count for lifecycle backups)
17. `ZT_CONTROLLER_STATE_DIR` (controller state source/restore path for backup workflows)
18. `ROUTE_SERVER_HOSTS` (comma-separated SSH targets, empty disables route-server fanout)
19. `ROUTE_SERVER_SSH_USER`
20. `ROUTE_SERVER_SSH_PORT`
21. `ROUTE_SERVER_SSH_PRIVATE_KEY_PATH`
22. `ROUTE_SERVER_SSH_CONNECT_TIMEOUT_SECONDS`
23. `ROUTE_SERVER_SSH_STRICT_HOST_KEY`
24. `ROUTE_SERVER_SSH_KNOWN_HOSTS_FILE`
25. `ROUTE_SERVER_REMOTE_CONFIG_DIR`
26. `ROUTE_SERVER_LOCAL_ASN`
27. `ZTIX_RUNTIME_CONFIG_PATH` (optional; defaults to `runtime-config.yaml`)

## 9.1 Required Runtime Configuration Keys (`runtime-config.yaml`)
1. `workflow.approval_mode`:
   - `manual_admin` (default)
   - `policy_auto` (optional)
2. `zerotier.self_hosted_controller.lifecycle.required_network_suffixes`:
   - list of 6-character lowercase hex suffixes,
   - backend composes full network IDs with runtime controller prefix from `GET /controller`,
   - repeated full network IDs in config should be avoided.
3. `zerotier.self_hosted_controller.ipv6.prefixes_by_network_suffix`:
   - mapping of required 6-character network suffix -> IPv6 `/64` prefix,
   - one mapping entry per required suffix (missing/extra/invalid entries fail lifecycle preflight),
   - deterministic allocator emits IPv6 `/128` addresses from this `/64` space.
4. Guardrail policy expansion for `policy_auto` is out of scope for `v0.1.0`; eligibility enforcement remains delegated to existing PeeringDB/local ASN + network authorization checks in request workflow validation.

## 10. Edge Cases
1. Callback replay with used `state`: reject and audit.
2. PeeringDB account with no eligible ASN: block request creation.
3. Local login with invalid password or unknown username: deterministic auth failure without user enumeration.
4. Local login for disabled credential: reject and audit.
5. CLI create user with duplicate username: deterministic conflict and no partial writes.
6. CLI assignment includes unknown `zt_network_id`: validation failure and no partial writes.
7. Concurrent approve/reject operations: first write wins, later action gets conflict.
8. Target ZeroTier network not found/inactive in configured provider: return failure with actionable admin guidance.
9. Provisioning timeout or rate limit: preserve error context and enforce bounded retry behavior.
10. Invalid provider mode or missing credentials: fail fast at startup with clear remediation logs.
11. Self-hosted controller lifecycle preflight failure: block provisioning and return actionable lifecycle remediation context.
12. Auth-related failures return JSON codes for SPA rendering and must not depend on backend redirect/error pages.
13. Suffix-only config includes malformed suffix or duplicate suffix values: reject preflight and emit actionable lifecycle audit metadata.
