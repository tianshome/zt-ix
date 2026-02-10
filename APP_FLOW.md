# Application Flow
Version: 0.3
Date: 2026-02-10

Related docs: `PRD.md`, `BACKEND_STRUCTURE.md`, `FRONTEND_GUIDELINES.md`, `IMPLEMENTATION_PLAN.md`

## 1. Screens and Routes
1. `/` Landing page
2. `/auth/login` Starts PeeringDB OAuth flow
3. `/auth/callback` OAuth callback handler
4. `/auth/local/login` Local username/password login handler (Auth Option A)
5. `/onboarding` ASN selection and join request form
6. `/dashboard` Operator status page
7. `/requests/:id` Operator request detail page
8. `/admin/requests` Admin queue/list page
9. `/admin/requests/:id` Admin request detail page
10. `/error` Recoverable error page

## 2. Status Model and Allowed Transitions
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

## 3. Primary Operator Authentication and Request Flow
Trigger: user authenticates from `/` using either PeeringDB OAuth or Auth Option A local credentials.

Auth Option B (PeeringDB OAuth) sequence:
1. User requests `/auth/login`.
2. App generates `state`, `nonce`, and PKCE verifier/challenge.
3. App redirects to PeeringDB authorization endpoint.
4. User authenticates and consents.
5. PeeringDB redirects to `/auth/callback?code=...&state=...`.
6. App validates callback state and exchanges code for token set.
7. App fetches profile and network authorization context from PeeringDB.
8. App upserts user and ASN mappings, then establishes local session.

Auth Option A (local credentials) sequence:
1. User submits username/password to `/auth/local/login`.
2. App normalizes username, verifies credential hash, and checks credential status.
3. App loads associated ASN/network assignments for the user.
4. App establishes local session.

Shared post-auth sequence:
1. Decision point:
   - Eligible ASN(s) found: redirect to `/onboarding`.
   - No eligible ASN: redirect to `/error` with support path.
2. User submits onboarding form (`asn`, `zt_network_id`, optional `node_id`, optional `notes`).
3. App validates ownership and duplicate constraints.
4. App creates `join_request` in `pending`, writes audit event, and redirects to `/requests/:id`.

Error branches:
1. Missing/invalid callback `state`: reject callback, audit, redirect `/error`.
2. Token exchange or upstream timeout: redirect `/error` with retry-login action.
3. Invalid local username/password: reject login with deterministic auth error and audit event.
4. Disabled local credential: reject login and return support path.
5. ASN ownership mismatch at submit time: show validation error, keep user on `/onboarding`.
6. Duplicate active request for same ASN/network: show deterministic conflict message with link to existing request.

## 4. Server CLI Local Account Provisioning Flow (Auth Option A)
Trigger: admin/operator with server shell access runs local provisioning command.

Sequence:
1. Actor runs CLI command (for example, `uv run python -m app.cli.users create ...`).
2. CLI validates required flags and mutually exclusive password input modes.
3. CLI creates or updates `app_user` and `local_credential`.
4. CLI sets optional `is_admin` and associated ASN/network assignments.
5. CLI emits audit event metadata for account-provisioning action.
6. Created user can authenticate through `/auth/local/login`.

Error branches:
1. Duplicate username: deterministic conflict output, no partial mutation.
2. Unknown associated network ID or invalid ASN input: validation error, no mutation.
3. Invalid password policy input: validation error, no mutation.

## 5. Admin Review Flow
Trigger: admin opens `/admin/requests`.

Sequence:
1. Admin views requests filtered by status/ASN/network.
2. Admin opens `/admin/requests/:id`.
3. Admin reviews operator identity, ASN context, and prior audit events.
4. Decision point:
   - Approve: set status `approved`, enqueue provisioning task, emit audit event.
   - Reject: require reason, set status `rejected`, emit audit event.
5. Operator sees updated status on `/requests/:id` and `/dashboard`.

Error branches:
1. Request already transitioned by another actor: conflict response with current status.
2. Missing reject reason: validation error, no mutation.
3. Non-admin caller on admin route: authorization failure.

## 6. Provisioning Flow
Trigger: request enters `approved`.

Sequence:
1. Worker dequeues job and atomically marks request `provisioning`.
2. Worker resolves provider mode (`central` or `self_hosted_controller`).
3. Worker calls provider adapter to authorize membership on target network.
4. Decision point:
   - Success: upsert membership data, set request `active`, emit audit event.
   - Failure: set request `failed`, increment retry metadata, emit audit event with error context.
5. Operator/admin UIs reflect final status and error details permitted by role.

Failure handling:
1. Transient provider/API failures may be retried by worker policy.
2. Terminal failures remain `failed` until admin explicitly retries.
3. Misconfiguration (invalid provider mode or missing credential) fails fast at startup and blocks worker processing.

## 7. Admin Retry Flow
Trigger: admin clicks retry on a `failed` request.

Sequence:
1. API validates request is currently `failed`.
2. API sets status back to `approved`.
3. API enqueues provisioning task and writes retry audit event.
4. Worker flow resumes at section 5.

Error branch:
1. Retry attempted from non-`failed` state: conflict response with current status.

## 8. Operator Return Flow
Trigger: authenticated operator visits `/dashboard`.

Sequence:
1. App lists operator-owned requests grouped by ASN.
2. Each row links to `/requests/:id`.
3. If no active request exists for an eligible ASN/network pair, onboarding action is available.

## 9. Route Guards
1. `/onboarding`, `/dashboard`, `/requests/:id`: authenticated user required.
2. `/admin/*`: admin role required.
3. `/auth/callback` and `/auth/local/login`: public routes with strict auth validation.
4. Cross-user access to `/requests/:id` returns denied/not-found behavior by policy.

## 10. UX Contract for Key Failures
1. Auth callback failure: show retry login action and short diagnostic code.
2. Duplicate request conflict: show existing request link instead of generic error.
3. Provisioning failure: show last error timestamp and admin remediation path.
4. Empty ASN eligibility: show why onboarding is blocked and how to get support.
5. Local login failure: show non-enumerating invalid-credential message.
