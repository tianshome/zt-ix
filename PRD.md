# Product Requirements Document (PRD)
Version: 0.7
Date: 2026-02-12
Product: ZT Internet Exchange (ZT-IX) Controller

Related docs: `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`, `IMPLEMENTATION_PLAN.md`

## 1. Objective
Build a self-service controller that lets verified network operators join a virtual IX fabric on ZeroTier, using PeeringDB OAuth and Auth Option A local credentials while keeping one canonical app user record, deterministic route-server desired config generation, repository-owned self-hosted ZeroTier controller lifecycle operations (bootstrap, network reconciliation, credential lifecycle, and backup/restore readiness), and a strict SPA frontend delivered separately from backend API services.

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
6. ZeroTier member provisioning through a provider abstraction with `self_hosted_controller` as the required release path.
7. Repository-owned self-hosted controller lifecycle operations:
   - controller runtime bootstrap/readiness checks,
   - managed network bootstrap/reconciliation,
   - controller auth token lifecycle controls,
   - backup/restore verification workflow.
8. Compatibility-only provider mode for migration/testing:
   - `central` (ZeroTier Central API token auth, non-release gate).
9. Route-server Option A desired-state generation:
   - generate explicit per-ASN BIRD peer snippets using assigned endpoint addresses,
   - sync snippets to each configured route server over SSH,
   - enforce ROA/RPKI validation checks in generated policy path.
10. Operator and admin UI for request lifecycle visibility using client-side routing only.
11. Audit logging for auth, decisions, provisioning actions, and controller lifecycle actions.
12. SPA runtime model:
   - frontend served by NGINX container in production,
   - NGINX reverse-proxies API traffic to FastAPI service container,
   - frontend uses fetch/XHR API calls (no backend-rendered pages).
13. Canonical ZeroTier network ID handling in owned self-hosted mode:
   - Python reads controller node ID prefix (first 10 hex characters) from controller API metadata at runtime.
   - Runtime configuration stores only 6-character network suffixes.
   - Full 16-character network IDs are composed in backend logic to avoid repeated full-ID literals and drift.

## 5. Out of Scope (Non-Goals)
1. Full multi-vendor BGP lifecycle orchestration beyond documented BIRD route-server Option A workflow.
2. Billing/invoicing.
3. Full NMS replacement.
4. Multi-cloud overlay orchestration outside ZeroTier.
5. Additional identity providers beyond PeeringDB OAuth and Auth Option A local credentials in phase 1.
6. Automated deployment/management of custom ZeroTier roots/planet infrastructure beyond the documented controller lifecycle ownership baseline.
7. Full i18n and advanced accessibility hardening beyond MVP for `v0.1.0`.

## 6. User Stories
1. As an operator, I can log in with PeeringDB so I do not create a separate identity.
2. As an operator, I can log in with a locally provisioned username/password account when PeeringDB OAuth is not used for that account.
3. As an operator, I can select my eligible ASN and request IX access.
4. As an admin, I can approve or reject requests with clear reasons.
5. As an admin, I can trigger ZeroTier authorization for approved requests through the owned self-hosted controller path in release environments.
6. As an admin/operator with server access, I can create local accounts from CLI with custom admin and associated ASN/network options.
7. As an operator, I can see whether my request is pending, provisioning, active, rejected, or failed.
8. As an auditor, I can view immutable logs of key actions.
9. As an admin, I can confirm route-server desired config was generated and synced for approved requests.
10. As an operations owner, I can verify controller readiness, rotate controller credentials, and execute backup/restore workflows with auditable outcomes.

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
1. SPA can initiate PeeringDB OAuth via backend API and receive authorization URL/context without backend redirect responses.
2. Callback validates `state` and `nonce` before session creation.
3. On OAuth success, local user is upserted by `peeringdb_user_id`.
4. Local users can authenticate with username/password using stored password hashes.
5. Local credential records are provisioned via server CLI only; public self-signup is not included in phase 1.
6. On auth errors, backend returns deterministic JSON error payloads and SPA shows recoverable inline login errors without redirecting to server error pages.
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
2. Release environments use `self_hosted_controller` mode; `central` is compatibility-only for migration/testing and not a release acceptance path.
3. Provisioning is idempotent for retries (no duplicate active membership rows).
4. Failures persist reason, last error timestamp, and retry count.
5. Success persists ZeroTier network/member identifiers and assigned addresses.
6. In self-hosted mode, backend derives full network IDs from live controller prefix + configured suffixes before network reconciliation/provisioning.
7. Config/release docs avoid repeated full network ID literals where a suffix reference is sufficient.

### F5. Admin Controls
Acceptance criteria:
1. Admins can list/filter requests by status, ASN, network, and age using MVP frontend-only table behavior in `v0.1.0`.
2. Large-scale table optimization (advanced pagination/sort persistence/virtualization) is deferred post-`v0.1.0`.
3. Admins can approve/reject with explicit audit event.
4. Admins can retry failed provisioning and view last known error context.

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

### F8. Route Server Desired Config Generation (Option A)
Acceptance criteria:
1. After successful member authorization, worker generates deterministic BIRD peer snippets per request/ASN and assigned endpoint IPs.
2. Generated snippets are synced to every configured route server over SSH.
3. Generated peer import policy path includes ROA/RPKI validation checks for both IPv4 and IPv6.
4. Route-server sync failures are captured with actionable error context and surfaced through request failure state + retry path.

### F9. Self-Hosted Controller Lifecycle Ownership
Acceptance criteria:
1. Startup/worker preflight verifies owned controller API/auth readiness and fails closed when prerequisites are missing.
2. Required ZeroTier network(s) are created/reconciled on the owned controller before request provisioning executes.
3. Controller auth token lifecycle operations (rotation/reload) are auditable and have deterministic failure handling.
4. Backup/restore workflow exists with a repeatable validation drill before provisioning resumes.
5. Release sign-off confirms self-hosted-only operation without dependency on ZeroTier Central credentials.
6. Required network reconciliation uses suffix-only configuration (`required_network_suffixes`) and runtime controller-prefix discovery.

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
   - MVP `v0.1.0` requires readable status text and keyboard-usable critical actions.
   - Full accessibility hardening and automated a11y checks are deferred post-`v0.1.0`.

## 10. Success Criteria
1. 90%+ of valid operator requests complete without manual backend intervention.
2. Median onboarding time from login to active membership is under 10 minutes on non-manual path.
3. Zero critical-severity security findings in auth/session handling.
4. 100% of approval/rejection/provisioning transitions appear in audit logs.
5. Release profile provisions through owned self-hosted controller lifecycle paths without requiring `ZT_CENTRAL_API_TOKEN`.
6. Controller backup/restore drill succeeds before `v0.1.0` release sign-off.

## 11. Constraints and Risks
1. PeeringDB scope/permission behavior can evolve; integration must keep parser logic isolated and test-backed.
2. ZeroTier provider credentials are high-impact secrets and require strict runtime secret handling.
3. Incorrect ASN authorization logic can cause unauthorized onboarding.
4. Provider API behavior differences can cause drift without explicit contract tests.
5. Local credential handling introduces password lifecycle and brute-force risk requiring test-backed controls.
6. Owning self-hosted controller lifecycle increases operational risk around state durability, credential rotation, and recovery drills.

## 12. Assumptions and Open Questions
1. Assumption: Phase 1 keeps admin approval as the default control path; policy auto-approval is not required for initial release.
2. Assumption: One request maps to one target ZeroTier network per submission.
3. Assumption: Auth Option A local accounts are created and managed from server CLI, not self-signup.
4. Assumption: release environments run `ZT_PROVIDER=self_hosted_controller`; `central` is compatibility-only.
5. Assumption: For local users, empty associated-network assignment means unrestricted network eligibility when no rows exist.
6. Assumption: frontend runtime is strict SPA; route ownership is client-side and backend serves JSON APIs only for UI workflows.
7. Requirement: approval behavior is runtime-configurable via `runtime-config.yaml` (`workflow.approval_mode` with `manual_admin` default and `policy_auto` optional).
8. Scope decision: detailed policy-auto guardrails are out of scope for `v0.1.0`; authorization relies on existing PeeringDB/local eligibility checks in backend workflow validation.
9. Open question: What minimum PeeringDB scope set is required in production if future API calls expand?
10. Open question: What controller runtime topology (single-node vs HA pair) is required for `v0.1.0`?
11. Open question: How should existing full-ID required-network config values be migrated to suffix-only form in rollout environments?

## 13. Definition of Done
1. All in-scope features meet acceptance criteria in this PRD.
2. Critical auth and provisioning paths have automated tests.
3. Deployment docs and runbook exist.
4. Security checklist completed for session, CSRF, and secret management.
5. Provisioning adapter contract tests cover `self_hosted_controller` release behavior and compatibility checks for `central` (if retained).
6. Local credential auth path and CLI provisioning path have automated test coverage.
7. Route-server desired config rendering and SSH fanout path have automated tests.
8. Owned self-hosted controller lifecycle paths (bootstrap/readiness, network reconciliation, token lifecycle, backup/restore validation) are implemented, audited, and test-backed.
9. SPA build/runtime delivery is implemented with NGINX frontend container and API reverse proxy wiring in production compose profile.
