# Backend Structure
Version: 0.1
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `IMPLEMENTATION_PLAN.md`

## 1. Architecture Overview
1. API server: FastAPI.
2. Relational storage: PostgreSQL.
3. Queue/worker: Celery + Redis for provisioning and reconciliation jobs.
4. External systems:
   - PeeringDB OIDC/OAuth and REST API.
   - ZeroTier provisioning provider: ZeroTier Central API or self-hosted ZeroTier controller API.

## 2. Database Schema (PostgreSQL)
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

## 3. Auth Logic
1. Initiate OIDC authorization flow with `state`, `nonce`, and PKCE.
2. On callback, validate `state` and exchange authorization code for tokens.
3. Use ID token/user info for identity; upsert `app_user`.
4. Use bearer access token to query PeeringDB APIs and populate `user_asn`.
5. Establish local session cookie (HTTP-only, Secure, SameSite=Lax).

## 4. ZeroTier Provisioning Provider Contract
1. Provisioning logic must consume a provider interface, not provider-specific call sites in workflow handlers.
2. Supported provider modes:
   - `central`: ZeroTier Central API token auth.
   - `self_hosted_controller`: ZeroTier local controller API auth via `X-ZT1-Auth`.
3. Provider interface returns normalized fields for persistence:
   - `member_id` (provider member identifier)
   - `is_authorized` (boolean)
   - `assigned_ips` (list of strings)
   - `provider_name` (mode string for logs/metrics)
4. Database schema remains unchanged for this decision; `zt_membership.member_id` stores provider-specific member identifier and must remain stable for idempotent retries.

## 5. API Contract (v1)
1. `GET /api/v1/me`
   - Returns current user profile and linked ASNs.
2. `GET /api/v1/asns`
   - Returns ASNs user can act on.
3. `POST /api/v1/requests`
   - Input: `asn`, `zt_network_id`, optional `node_id`, optional `notes`.
   - Output: created request with `pending` status.
4. `GET /api/v1/requests`
   - List current user requests.
5. `GET /api/v1/requests/{request_id}`
   - Return request detail including membership (if active).
6. `POST /api/v1/admin/requests/{request_id}/approve`
   - Admin-only. Marks approved and queues provisioning job.
7. `POST /api/v1/admin/requests/{request_id}/reject`
   - Admin-only. Requires `reject_reason`.
8. `POST /api/v1/admin/requests/{request_id}/retry`
   - Admin-only. Requeues failed request.

## 6. Storage and Secret Rules
1. ZeroTier provider secrets (Central API token or self-hosted controller auth token) must never be stored in plaintext DB rows.
2. Secret source: environment secret manager at runtime.
3. `ZT_PROVIDER` selects provider mode; startup validation must fail if required provider credentials are missing.
4. OAuth transient values (`state`, `nonce`, verifier) are short-lived and purged after use or expiration.
5. Access tokens from PeeringDB are stored encrypted only if needed for asynchronous refresh; otherwise keep in server session.

## 7. Edge Cases
1. Callback replay with used `state`: reject and audit.
2. PeeringDB account with no eligible ASN: block request creation.
3. Concurrent approval actions: first write wins, second receives conflict response.
4. ZeroTier network not found or inactive in the configured provider: fail fast before queueing.
5. Provisioning timeout: status `failed`, increment retry counter, retain error context.
6. Invalid provider mode or missing provider credentials: fail fast at app startup and log explicit remediation guidance.
