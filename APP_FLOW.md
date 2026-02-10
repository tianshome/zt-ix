# Application Flow
Version: 0.1
Date: 2026-02-10

Related docs: `PRD.md`, `BACKEND_STRUCTURE.md`, `FRONTEND_GUIDELINES.md`, `IMPLEMENTATION_PLAN.md`

## 1. Screens and Routes
1. `/` Landing page
2. `/auth/login` Starts PeeringDB OIDC flow
3. `/auth/callback` OIDC callback handler
4. `/onboarding` ASN selection + join request form
5. `/dashboard` Operator status page
6. `/requests/:id` Request detail page
7. `/admin/requests` Admin queue/list page
8. `/admin/requests/:id` Admin request detail page
9. `/error` Recoverable error page

## 2. Primary Operator Flow
Trigger: User clicks "Sign in with PeeringDB" on `/`.

Sequence:
1. User goes to `/auth/login`.
2. App creates `state`, `nonce`, and PKCE verifier/challenge.
3. App redirects user to PeeringDB auth endpoint.
4. User authenticates and consents.
5. PeeringDB redirects to `/auth/callback?code=...&state=...`.
6. App validates `state`; exchanges `code` for tokens.
7. App reads user identity and authorized network context.
8. Success:
   - If eligible ASN found -> redirect to `/onboarding`.
   - If none found -> redirect to `/error` with actionable reason.
9. User selects ASN and submits request on `/onboarding`.
10. App creates request record in `pending`.
11. User lands on `/requests/:id` with live status.

Error branches:
1. Invalid/missing `state` -> `/error` with retry login.
2. Token exchange failure -> `/error` with retry login.
3. API timeout -> `/error` with transient retry message.

## 3. Admin Review Flow
Trigger: Admin opens `/admin/requests`.

Sequence:
1. Admin views pending requests list.
2. Admin opens `/admin/requests/:id`.
3. Admin reviews ASN + identity context + policy checks.
4. Decision point:
   - Approve: request status -> `approved`, provisioning job queued.
   - Reject: request status -> `rejected`, reason required.
5. Audit event is written for decision.
6. User sees updated status on `/requests/:id`.

Error branches:
1. Request already processed -> show conflict and latest state.
2. Missing reject reason -> validation error, no state change.

## 4. Provisioning Flow
Trigger: Request enters `approved`.

Sequence:
1. Worker picks provisioning job.
2. App resolves configured ZeroTier provider (`central` or `self_hosted_controller`).
3. App calls the selected provider for target network membership authorization.
4. Decision point:
   - Provider success -> status `active`, save member details.
   - Provider failure -> status `failed`, store error and retry metadata.
5. Audit event and operational logs written.
6. Operator dashboard reflects final state.

Error branches:
1. Rate limit or timeout -> retry with backoff.
2. Permanent validation failure -> terminal `failed`, manual requeue available.
3. Provider misconfiguration or unavailable controller endpoint -> terminal `failed` with actionable admin retry/remediation path.

## 5. Operator Return Flow
Trigger: Authenticated operator visits `/dashboard`.

Sequence:
1. App lists all requests by ASN.
2. Each row links to `/requests/:id`.
3. If no active request for eligible ASN, operator can start new onboarding request.

## 6. Route Guard Rules
1. `/onboarding`, `/dashboard`, `/requests/:id`: authenticated user required.
2. `/admin/*`: admin role required.
3. `/auth/callback`: public route with strict OAuth validation only.

## 7. State Model
1. `pending` - submitted, waiting admin/policy.
2. `approved` - approved, queued for provisioning.
3. `provisioning` - active worker processing.
4. `active` - membership confirmed.
5. `rejected` - admin/policy denied.
6. `failed` - provisioning failed and requires retry or remediation.
