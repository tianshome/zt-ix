# Backend Structure
Version: 0.4
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `IMPLEMENTATION_PLAN.md`

## 1. Architecture Overview
1. API server: FastAPI.
2. Relational storage: PostgreSQL.
3. Queue and worker: Celery + Redis for provisioning and reconciliation jobs.
4. External systems:
   - PeeringDB OAuth endpoints and PeeringDB REST API.
   - ZeroTier provisioning provider (`central` or `self_hosted_controller`).
5. Authentication modes:
   - Auth Option A: local credentials stored in DB (`local_credential`) with `app_user` as canonical user profile.
   - Auth Option B: PeeringDB OAuth identities mapped onto canonical `app_user`.

## 2. Core Domain Invariants
1. Canonical application user identity is `app_user.id` (UUID).
2. `app_user.peeringdb_user_id` is unique when present and nullable for local-only users.
3. Local credential usernames are unique after normalization (lowercase and trimmed).
4. A user can only create requests for ASNs currently linked to that user from either PeeringDB sync or local assignment.
5. If user-level associated-network rows exist, request target network must be within that association set.
6. Only one active request exists per (`asn`, `zt_network_id`) across statuses:
   - `pending`, `approved`, `provisioning`, `active`
7. Request state transitions must follow `APP_FLOW.md`.
8. `zt_membership` is one-to-one with `join_request` and unique per (`zt_network_id`, `node_id`).

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
  id TEXT PRIMARY KEY CHECK (char_length(id) = 16),
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
  node_id TEXT CHECK (node_id IS NULL OR char_length(node_id) = 10),
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
  node_id TEXT NOT NULL CHECK (char_length(node_id) = 10),
  member_id TEXT NOT NULL,
  is_authorized BOOLEAN NOT NULL DEFAULT FALSE,
  assigned_ips TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (zt_network_id, node_id)
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
CREATE UNIQUE INDEX uq_join_request_active_per_asn_network
  ON join_request(asn, zt_network_id)
  WHERE status IN ('pending', 'approved', 'provisioning', 'active');
CREATE INDEX idx_audit_event_created_at ON audit_event(created_at);
CREATE INDEX idx_local_credential_user_id ON local_credential(user_id);
CREATE INDEX idx_user_network_access_user_id ON user_network_access(user_id);
```

## 4. Authentication and Session Contract
1. Auth Option B (`/auth/login`, `/auth/callback`) starts OAuth authorization with `state`, `nonce`, and PKCE verifier.
2. OAuth callback validates `state`, exchanges code for token set, and consumes one-time state row.
3. Auth Option A (`/auth/local/login`) verifies username/password against `local_credential.password_hash`.
4. Identity and ASN/network authorization context are loaded from:
   - PeeringDB profile/API for OAuth users.
   - persisted local assignments for local-credential users.
5. Local session cookie requirements:
   - HTTP-only
   - Secure in production
   - SameSite=Lax
6. Replay protection:
   - Callback with used or expired `state` is rejected and audited.
7. Local credential verification requirements:
   - passwords stored as salted hashes only
   - constant-time comparison for verification path
   - disabled credentials cannot establish sessions

## 5. ZeroTier Provisioning Provider Contract
1. Workflow code depends on provider interface, not provider-specific endpoints.
2. Supported provider modes:
   - `central`: ZeroTier Central API (`Authorization: token <token>`)
   - `self_hosted_controller`: local controller API (`X-ZT1-Auth: <token>`)
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

## 5.1 Route Server Option A Contract (Sub-phase 5B)
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
1. `GET /api/v1/me`
   - Auth: user session required.
   - `200`: user profile + linked ASNs.
   - `401`: unauthenticated.
2. `GET /api/v1/asns`
   - Auth: user session required.
   - `200`: eligible ASN list.
   - `401`: unauthenticated.
3. `POST /api/v1/requests`
   - Auth: user session required.
   - Body: `asn`, `zt_network_id`, optional `node_id`, optional `notes`.
   - `201`: request created in `pending`.
   - `400`: validation error.
   - `403`: ASN not authorized for user.
   - `409`: duplicate active request.
4. `GET /api/v1/requests`
   - Auth: user session required.
   - `200`: user-owned request list.
5. `GET /api/v1/requests/{request_id}`
   - Auth: user session required.
   - `200`: request detail + membership if present.
   - `404`: not found or not visible to caller.
6. `POST /api/v1/admin/requests/{request_id}/approve`
   - Auth: admin required.
   - `200`: status set `approved`, job queued.
   - `403`: not admin.
   - `409`: invalid current state.
7. `POST /api/v1/admin/requests/{request_id}/reject`
   - Auth: admin required.
   - Body: `reject_reason` required.
   - `200`: status set `rejected`.
   - `400`: missing reason.
   - `403`: not admin.
   - `409`: invalid current state.
8. `POST /api/v1/admin/requests/{request_id}/retry`
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

## 8. Storage and Secret Rules
1. Provider secrets (Central API token or controller auth token) are never stored in plaintext DB rows.
2. Secret source is runtime environment or external secret manager.
3. `ZT_PROVIDER` selects provider mode; startup validation fails if mode is invalid or required credentials are missing.
4. OAuth transient values (`state`, `nonce`, verifier) are short-lived and purged after use or expiry.
5. PeeringDB access tokens are stored encrypted only when required for async behavior; otherwise kept in session context only.
6. Local password material is stored only as non-reversible hashes and never logged.

## 9. Required Environment Variables
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
11. `ZT_CONTROLLER_AUTH_TOKEN` (required when `ZT_PROVIDER=self_hosted_controller`)
12. `ROUTE_SERVER_HOSTS` (comma-separated SSH targets, empty disables route-server fanout)
13. `ROUTE_SERVER_SSH_USER`
14. `ROUTE_SERVER_SSH_PORT`
15. `ROUTE_SERVER_SSH_PRIVATE_KEY_PATH`
16. `ROUTE_SERVER_SSH_CONNECT_TIMEOUT_SECONDS`
17. `ROUTE_SERVER_SSH_STRICT_HOST_KEY`
18. `ROUTE_SERVER_SSH_KNOWN_HOSTS_FILE`
19. `ROUTE_SERVER_REMOTE_CONFIG_DIR`
20. `ROUTE_SERVER_LOCAL_ASN`

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
