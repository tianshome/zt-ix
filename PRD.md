# Product Requirements Document (PRD)
Version: 0.3
Date: 2026-02-10
Product: ZT Internet Exchange (ZT-IX) Controller

Related docs: `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`, `IMPLEMENTATION_PLAN.md`

## 1. Objective
Build a self-service controller that lets verified network operators join a virtual IX fabric on ZeroTier, using PeeringDB OAuth and Auth Option A local credentials while keeping one canonical app user record and a configurable ZeroTier provisioning provider.

## 2. Target Users
1. Network operators who maintain ASN records in PeeringDB.
2. IX administrators who control acceptance and policy.
3. NOC/operations staff who need clear provisioning status and auditability.

## 3. Problem Statement
Virtual IX onboarding is often manual and inconsistent. Operators need a standardized flow to prove identity, request access, and get provisioned into a ZeroTier-based peering fabric with minimal human overhead and strong controls.

## 4. In Scope
1. PeeringDB OAuth login flow and local session establishment.
2. Auth Option A local username/password login flow for pre-provisioned users.
3. Server CLI account provisioning for local users, including admin flag and associated ASN/network assignments.
4. ASN and network-context retrieval from PeeringDB APIs for PeeringDB-authenticated users.
5. Join request workflow (`pending`, review, approve/reject, provisioning outcomes).
6. ZeroTier member provisioning through a provider abstraction.
7. Phase 1 provider modes:
   - `central` (ZeroTier Central API token auth)
   - `self_hosted_controller` (local controller API with auth token)
8. Operator and admin UI for request lifecycle visibility.
9. Audit logging for auth, decisions, and provisioning actions.

## 5. Out of Scope (Non-Goals)
1. BGP session orchestration across routers.
2. Billing/invoicing.
3. Full NMS replacement.
4. Multi-cloud overlay orchestration outside ZeroTier.
5. Additional identity providers beyond PeeringDB OAuth and Auth Option A local credentials in phase 1.
6. Automated deployment/management of custom ZeroTier roots/planet infrastructure.

## 6. User Stories
1. As an operator, I can log in with PeeringDB so I do not create a separate identity.
2. As an operator, I can log in with a locally provisioned username/password account when PeeringDB OAuth is not used for that account.
3. As an operator, I can select my eligible ASN and request IX access.
4. As an admin, I can approve or reject requests with clear reasons.
5. As an admin, I can trigger ZeroTier authorization for approved requests through the configured provider.
6. As an admin/operator with server access, I can create local accounts from CLI with custom admin and associated ASN/network options.
7. As an operator, I can see whether my request is pending, provisioning, active, rejected, or failed.
8. As an auditor, I can view immutable logs of key actions.

## 7. Roles and Permissions
1. Operator:
   - Can authenticate, list own eligible ASNs, create/view own requests.
   - Cannot approve/reject/retry requests.
2. Admin:
   - Can list all requests, approve/reject, retry failed provisioning.
   - Can view request and audit context needed for decisions.
3. System worker:
   - Can transition approved requests through provisioning states.
   - Cannot bypass authorization checks or mutate unrelated request fields.

## 8. Features and Acceptance Criteria

### F1. Authentication (PeeringDB + Auth Option A Local Credentials)
Acceptance criteria:
1. User can initiate login via PeeringDB OAuth endpoints.
2. Callback validates `state` and `nonce` before session creation.
3. On OAuth success, local user is upserted by `peeringdb_user_id`.
4. Local users can authenticate with username/password using stored password hashes.
5. Local credential records are provisioned via server CLI only; public self-signup is not included in phase 1.
6. On auth errors, user is sent to recoverable error path with retry action.
7. Requested OAuth scopes are explicitly documented and tested.

### F2. ASN Discovery and Eligibility
Acceptance criteria:
1. System fetches user identity and authorized network context from PeeringDB for OAuth-authenticated users.
2. System uses locally assigned ASN/network associations for Auth Option A local users.
3. User can submit requests only for ASNs they are authorized to represent.
4. If associated network restrictions are configured for a user, submissions must match those associations.
5. If no eligible ASN is found, UI shows explicit reason and support path.

### F3. Join Request Workflow
Acceptance criteria:
1. Operator can create one active request per ASN per target IX network.
2. Duplicate in-flight requests return deterministic conflict message.
3. Request status transitions are strictly enforced:
   - `pending -> approved|rejected`
   - `approved -> provisioning`
   - `provisioning -> active|failed`
   - `failed -> approved` (admin retry path)
4. Rejection requires reason text and creates an audit record.

### F4. ZeroTier Provisioning
Acceptance criteria:
1. Approved request triggers a provider-agnostic member-authorization task.
2. Provider mode is selected by config (`central` or `self_hosted_controller`) with no workflow-state differences.
3. Provisioning is idempotent for retries (no duplicate active membership rows).
4. Failures persist reason, last error timestamp, and retry count.
5. Success persists ZeroTier network/member identifiers and assigned addresses.

### F5. Admin Controls
Acceptance criteria:
1. Admins can list/filter requests by status, ASN, network, and age.
2. Admins can approve/reject with explicit audit event.
3. Admins can retry failed provisioning and view last known error context.

### F6. Auditing and Observability
Acceptance criteria:
1. Every auth event, request status change, and provisioning attempt emits an audit event.
2. Audit event captures actor, action, target, timestamp, and metadata.
3. Operational logs include request IDs and upstream correlation data when available.

### F7. Security Baseline
Acceptance criteria:
1. Session cookies are HTTP-only and Secure in production.
2. State-changing requests enforce CSRF protections.
3. Provider credentials are sourced from runtime secrets, never persisted in plaintext DB rows.
4. Local passwords are never stored in plaintext and are verified with constant-time comparison.
5. Unauthorized access to another user's request returns denied/not-found behavior by policy.

## 9. Non-Functional Requirements
1. Reliability:
   - Provisioning jobs are retry-safe and idempotent.
   - Startup fails fast if provider mode is invalid or required credentials are missing.
2. Performance:
   - Auth callback and request-creation endpoints should return interactive responses under normal load (no long-running provider calls inline).
3. Observability:
   - Admin-facing and operator-facing failures include actionable status text.
   - Worker logs expose enough context for post-incident tracing.
4. Accessibility:
   - UI must meet the baseline in `FRONTEND_GUIDELINES.md` for contrast, focus, and status semantics.

## 10. Success Criteria
1. 90%+ of valid operator requests complete without manual backend intervention.
2. Median onboarding time from login to active membership is under 10 minutes on non-manual path.
3. Zero critical-severity security findings in auth/session handling.
4. 100% of approval/rejection/provisioning transitions appear in audit logs.

## 11. Constraints and Risks
1. PeeringDB scope/permission behavior can evolve; integration must keep parser logic isolated and test-backed.
2. ZeroTier provider credentials are high-impact secrets and require strict runtime secret handling.
3. Incorrect ASN authorization logic can cause unauthorized onboarding.
4. Provider API behavior differences can cause drift without explicit contract tests.
5. Local credential handling introduces password lifecycle and brute-force risk requiring test-backed controls.

## 12. Assumptions and Open Questions
1. Assumption: Phase 1 keeps admin approval as the default control path; policy auto-approval is not required for initial release.
2. Assumption: One request maps to one target ZeroTier network per submission.
3. Assumption: Auth Option A local accounts are created and managed from server CLI, not self-signup.
4. Open question: Should policy-based auto-approval be a phase 1.1 scope item or deferred to a later phase?
5. Open question: For local users, should empty associated-network assignment mean unrestricted network eligibility or deny-by-default?
6. Open question: What minimum PeeringDB scope set is required in production if future API calls expand?

## 13. Definition of Done
1. All in-scope features meet acceptance criteria in this PRD.
2. Critical auth and provisioning paths have automated tests.
3. Deployment docs and runbook exist.
4. Security checklist completed for session, CSRF, and secret management.
5. Provisioning adapter contract tests cover both `central` and `self_hosted_controller` modes.
6. Local credential auth path and CLI provisioning path have automated test coverage.
