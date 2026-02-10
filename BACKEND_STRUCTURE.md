# Backend Structure
Version: 0.2
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `IMPLEMENTATION_PLAN.md`

## 1. Architecture Overview
1. API server: FastAPI.
2. Relational storage: PostgreSQL.
3. Queue and worker: Celery + Redis for provisioning and reconciliation jobs.
4. External systems:
   - PeeringDB OAuth endpoints and PeeringDB REST API.
   - ZeroTier provisioning provider (`central` or `self_hosted_controller`).

## 2. Core Domain Invariants
1. A user is uniquely identified by `peeringdb_user_id`.
2. A user can only create requests for ASNs currently linked to that user from PeeringDB.
3. Only one active request exists per (`asn`, `zt_network_id`) across statuses:
   - `pending`, `approved`, `provisioning`, `active`
4. Request state transitions must follow `APP_FLOW.md`.
5. `zt_membership` is one-to-one with `join_request` and unique per (`zt_network_id`, `node_id`).

## 3. Database Schema (PostgreSQL)
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE app_user (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  peeringdb_user_id BIGINT NOT NULL UNIQUE,
  username TEXT NOT NULL,
  full_name TEXT,
  email TEXT,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
```

## 4. Authentication and Session Contract
1. `/auth/login` starts OAuth authorization with `state`, `nonce`, and PKCE verifier.
2. `/auth/callback` validates `state`, exchanges code for token set, and consumes one-time state row.
3. Identity and ASN authorization context are loaded from PeeringDB profile/API calls before request creation is allowed.
4. Local session cookie requirements:
   - HTTP-only
   - Secure in production
   - SameSite=Lax
5. Replay protection:
   - Callback with used or expired `state` is rejected and audited.

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

## 9. Required Environment Variables
1. `APP_SECRET_KEY`
2. `DATABASE_URL`
3. `REDIS_URL`
4. `PEERINGDB_CLIENT_ID`
5. `PEERINGDB_CLIENT_SECRET`
6. `PEERINGDB_REDIRECT_URI`
7. `ZT_PROVIDER` (`central|self_hosted_controller`)
8. `ZT_CENTRAL_API_TOKEN` (required when `ZT_PROVIDER=central`)
9. `ZT_CONTROLLER_BASE_URL` (required when `ZT_PROVIDER=self_hosted_controller`)
10. `ZT_CONTROLLER_AUTH_TOKEN` (required when `ZT_PROVIDER=self_hosted_controller`)

## 10. Edge Cases
1. Callback replay with used `state`: reject and audit.
2. PeeringDB account with no eligible ASN: block request creation.
3. Concurrent approve/reject operations: first write wins, later action gets conflict.
4. Target ZeroTier network not found/inactive in configured provider: return failure with actionable admin guidance.
5. Provisioning timeout or rate limit: preserve error context and enforce bounded retry behavior.
6. Invalid provider mode or missing credentials: fail fast at startup with clear remediation logs.
