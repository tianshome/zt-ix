# Application Flow
Version: 1.0
Date: 2026-02-12

Related docs: `PRD.md`, `BACKEND_STRUCTURE.md`, `FRONTEND_GUIDELINES.md`, `IMPLEMENTATION_PLAN.md`

## 1. Route Ownership and Runtime
1. Frontend route ownership is client-side only (SPA router).
2. Backend serves JSON APIs only for workflow/auth/data operations.
3. Production runtime:
   - SPA static assets are served by NGINX container.
   - NGINX reverse-proxies API traffic to FastAPI container.
4. Development runtime:
   - `vite serve` hosts SPA.
   - Vite dev proxy forwards API calls to `http://localhost:8000`.

## 2. Browser Routes (SPA)
1. `/` App shell entry.
2. `/login` Auth selection and credential form.
3. `/auth/callback` OAuth callback processing view.
4. `/onboarding` ASN selection and join request form.
5. `/dashboard` Operator status page.
6. `/requests/:id` Operator request detail page.
7. `/admin/requests` Admin queue/list page.
8. `/admin/requests/:id` Admin request detail page.

## 3. Backend API Routes Used by Frontend
1. `POST /api/v1/auth/peeringdb/start`
2. `POST /api/v1/auth/peeringdb/callback`
3. `POST /api/v1/auth/local/login`
4. `POST /api/v1/auth/logout`
5. `GET /api/v1/onboarding/context`
6. `GET /api/v1/me`
7. `GET /api/v1/asns`
8. `POST /api/v1/requests`
9. `GET /api/v1/requests`
10. `GET /api/v1/requests/{request_id}`
11. `GET /api/v1/admin/requests`
12. `GET /api/v1/admin/requests/{request_id}`
13. `POST /api/v1/admin/requests/{request_id}/approve`
14. `POST /api/v1/admin/requests/{request_id}/reject`
15. `POST /api/v1/admin/requests/{request_id}/retry`

## 4. Status Model and Allowed Transitions
1. `pending`: submitted, awaiting admin decision.
2. `approved`: approved and queued for worker pickup.
3. `provisioning`: worker is actively processing.
4. `active`: provider membership authorization confirmed.
5. `rejected`: denied by admin or policy.
6. `failed`: provisioning failed; admin may retry.

Allowed transitions:
1. `pending -> approved`
2. `pending -> rejected`
3. `approved -> provisioning`
4. `provisioning -> active`
5. `provisioning -> failed`
6. `failed -> approved` (admin retry path)

Forbidden transitions return conflict errors and do not mutate data.

## 4.1 ZeroTier ID Canonicalization
1. `node_id` means ZeroTier node address (10 lowercase hex characters).
2. `zt_network_id` means full ZeroTier network ID (16 lowercase hex characters).
3. In self-hosted mode, controller-managed network IDs are derived in backend runtime as:
   - `full_network_id = controller_prefix(10 hex from /controller) + configured_suffix(6 hex from runtime-config.yaml)`.
4. Runtime config stores suffixes only to avoid repetitive full network ID literals and prefix drift across docs/config.

## 5. Primary Operator Authentication and Request Flow
Trigger: user authenticates from `/login` using either PeeringDB OAuth or Auth Option A local credentials.

Auth Option B (PeeringDB OAuth) sequence:
1. SPA calls `POST /api/v1/auth/peeringdb/start`.
2. API creates `state`, `nonce`, and PKCE verifier/challenge and returns OAuth authorization URL.
3. SPA navigates browser to returned PeeringDB authorization URL.
4. PeeringDB redirects browser to SPA route `/auth/callback?code=...&state=...`.
5. SPA calls `POST /api/v1/auth/peeringdb/callback` with callback payload.
6. API validates callback state and nonce and exchanges code for token set.
7. API fetches profile and network authorization context from PeeringDB.
8. API upserts user and ASN mappings, then establishes local session.
9. SPA routes user to `/onboarding` (or keeps user on `/login` with inline error state).

Auth Option A (local credentials) sequence:
1. SPA submits username/password to `POST /api/v1/auth/local/login`.
2. API normalizes username, verifies credential hash, and checks credential status.
3. API loads associated ASN/network assignments for the user.
4. API establishes local session and returns success payload.
5. SPA routes user to `/onboarding`.

Shared post-auth sequence:
1. SPA calls `GET /api/v1/onboarding/context`.
2. Decision point:
   - Eligible ASN(s) found: remain in onboarding flow.
   - No eligible ASN: show inline blocked-state message and support path in SPA.
3. User submits onboarding form (`asn`, `zt_network_id`, optional `node_id`, optional `notes`) to `POST /api/v1/requests`.
4. API validates ownership and duplicate constraints.
5. API creates `join_request` in `pending`, writes audit event, and returns request payload.
6. SPA navigates to `/requests/:id`.

Error branches:
1. Missing/invalid callback `state`: API rejects callback, audits event, and returns deterministic JSON error code.
2. Token exchange or upstream timeout: API returns retryable JSON error; SPA presents inline retry action.
3. Invalid local username/password: API returns deterministic auth error and writes audit event.
4. Disabled local credential: API returns support-path error code.
5. ASN ownership mismatch at submit time: API returns validation error and SPA keeps user on `/onboarding`.
6. Duplicate active request for same ASN/network/`node_id` key: API returns deterministic conflict including existing request reference.

## 6. Server CLI Local Account Provisioning Flow (Auth Option A)
Trigger: admin/operator with server shell access runs local provisioning command.

Sequence:
1. Actor runs CLI command (for example, `uv run python -m app.cli.users create ...`).
2. CLI validates required flags and mutually exclusive password input modes.
3. CLI creates or updates `app_user` and `local_credential`.
4. CLI sets optional `is_admin` and associated ASN/network assignments.
5. CLI emits audit event metadata for account-provisioning action.
6. Created user can authenticate through SPA login using `POST /api/v1/auth/local/login`.

Error branches:
1. Duplicate username: deterministic conflict output, no partial mutation.
2. Unknown associated network ID or invalid ASN input: validation error, no mutation.
3. Invalid password policy input: validation error, no mutation.

## 7. Admin Review Flow
Trigger: admin opens `/admin/requests`.

Sequence:
1. SPA loads queue data from `GET /api/v1/admin/requests` with optional filters.
2. Admin opens `/admin/requests/:id`.
3. SPA loads detail data from `GET /api/v1/admin/requests/{request_id}`.
4. Admin reviews operator identity, ASN context, and prior audit events.
5. Decision point:
   - Approve: `POST /api/v1/admin/requests/{id}/approve`, queue provisioning, emit audit event.
   - Reject: `POST /api/v1/admin/requests/{id}/reject` with reason, emit audit event.
6. SPA refreshes/polls detail/list endpoints to reflect updated status.

Error branches:
1. Request already transitioned by another actor: conflict response with current status.
2. Missing reject reason: validation error, no mutation.
3. Non-admin caller on admin route/API: authorization failure.

## 8. Controller Lifecycle Preflight and Operations Flow (Owned Self-Hosted Mode)
Trigger: API/worker startup and scheduled controller-operations jobs.

Sequence:
1. Service preflight verifies self-hosted controller API reachability and authentication.
2. Service reads controller metadata (`/controller`) and captures controller node prefix (first 10 hex characters).
3. Service composes required full network IDs from configured suffix list (`required_network_suffixes`).
4. Service verifies required controller-managed network context and reconciles when missing/drifted.
5. Decision point:
   - Preflight success: provisioning queue consumption remains enabled.
   - Preflight failure: fail closed for provisioning paths and surface actionable admin diagnostics.
6. Controller lifecycle operations (scheduled or manually triggered by runbook):
   - credential/token lifecycle actions,
   - backup artifact creation/retention checks,
   - restore validation drill before provisioning resume.
7. Lifecycle actions emit audit events with actor/system metadata and outcome.

Error branches:
1. Controller auth/reachability failure: block provisioning and require remediation.
2. Invalid configured suffix (non-hex, wrong length, duplicate) or composed network/prefix mismatch: block provisioning and surface failure context.
3. Required controller network missing and reconciliation fails: block provisioning and surface failure context.
4. Backup/restore validation failure: keep controller lifecycle in blocked state until validation passes.

## 9. Provisioning Flow
Trigger: request enters `approved`.

Sequence:
1. Worker dequeues job and atomically marks request `provisioning`.
2. Worker resolves provider mode from `ZT_PROVIDER` (release environments require `self_hosted_controller`; `central` is compatibility-only).
3. For self-hosted mode, worker enforces controller lifecycle readiness gate before provider calls.
4. For self-hosted mode, worker allocates/reuses deterministic IPv6 assignment from SQL-backed per-network/per-ASN sequence state.
5. Worker calls provider adapter to authorize membership on target network using explicit IPv6 `ipAssignments` and `noAutoAssignIps=true`.
6. In self-hosted mode, lifecycle reconciliation ensures each required network config includes the configured IPv6 `/64` managed route and has IPv4 auto-assignment disabled.
7. Worker renders deterministic per-ASN route-server BIRD peer snippets using assigned endpoint addresses.
8. Worker fans out generated snippets over SSH to all configured route servers.
9. Decision point:
   - Success: upsert membership data, set request `active`, emit audit events.
   - Failure: set request `failed`, increment retry metadata, emit audit event with error context.
10. Operator/admin SPA views observe status via polling APIs.

Failure handling:
1. Transient provider/API failures may be retried by worker policy.
2. Terminal failures remain `failed` until admin explicitly retries.
3. Route-server SSH/sync failures are treated as provisioning failures with actionable details.
4. Misconfiguration (invalid provider mode, missing credential, or failed lifecycle preflight) fails fast and blocks worker processing.

## 10. Admin Retry Flow
Trigger: admin clicks retry on a `failed` request.

Sequence:
1. API validates request is currently `failed`.
2. API sets status back to `approved`.
3. API enqueues provisioning task and writes retry audit event.
4. Worker flow resumes at section 9.

Error branch:
1. Retry attempted from non-`failed` state: conflict response with current status.

## 11. Request Status Refresh Contract
1. SPA uses HTTP GET polling only for status refresh in `v0.1.0`.
2. No websocket/SSE transport is required in `v0.1.0`.
3. Polling intervals are frontend-configurable and must use bounded cadence.

## 12. Route Guards
1. Client routes `/onboarding`, `/dashboard`, `/requests/:id`: authenticated session required.
2. Client routes `/admin/*`: admin role required.
3. API routes enforce session/role checks regardless of client behavior.
4. Cross-user access to `/api/v1/requests/{request_id}` returns denied/not-found behavior by policy.

## 13. UX Contract for Key Failures
1. Auth callback failure: show inline retry login action and short diagnostic code in SPA.
2. Duplicate request conflict: show existing request link/action in SPA instead of generic error.
3. Provisioning failure: show last error timestamp and admin remediation path.
4. Empty ASN eligibility: show why onboarding is blocked and how to get support.
5. Local login failure: show non-enumerating invalid-credential message.
6. Server `/error` page is not used; error messaging is frontend-owned.
7. Error/status copy is localized through frontend message catalogs (i18n-enabled) instead of hard-coded route text.

## 14. Localization and Branding Contract
1. Locale detection order:
   - first supported locale in `navigator.languages`,
   - fallback to `navigator.language`,
   - fallback to first configured locale when no supported match exists.
2. Locale switcher:
   - available in persistent shell/header UI,
   - shows at least `en-US`, `zh-CN`, `he` with flag emoji labels,
   - user selection overrides auto-detection for the active session/profile preference.
3. Right-to-left behavior:
   - selecting `he` applies document/SPA RTL direction handling.
4. UX copy contract:
   - user-visible labels and helper text must avoid internal implementation jargon (for example phase/step terminology).
5. Branding contract:
   - app name/logo/support/github URL are sourced from a compile-time branding configuration file consumed by frontend build.
