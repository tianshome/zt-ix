# Implementation Plan
Version: 0.4
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## 1. Planning Assumptions and Open Questions
1. Assumption: phase 1 uses admin approval as default decision control.
2. Assumption: provider mode is selected by `ZT_PROVIDER` and cannot be switched per-request.
3. Assumption: local development uses the following dependency profile:
   - Docker Compose for PostgreSQL/Redis only
   - API and worker run directly via `uv run`
4. Assumption: authentication planning follows "Auth Option A" (local credentials table, canonical `app_user`, server CLI provisioning) and "Auth Option B" (PeeringDB OAuth).
5. Assumption: route-server automation in this plan follows "Route Server Option A" (worker-driven SSH orchestration to remote Ubuntu/Linux route servers).
6. Requirement: each approved ASN must produce explicit generated BIRD peer config on every configured route server.
7. Requirement: generated BIRD policy path must enable ROA/RPKI validation for route acceptance decisions.
8. Open question: policy-based auto-approval scope (if any) remains deferred pending product decision.
9. Open question: target retry limits/backoff constants should be finalized before phase 5 implementation.
10. Open question: for Auth Option A, does empty associated-network assignment mean unrestricted access or deny-by-default?

## 1.1 Option Labels (Disambiguation)
1. Auth Option A:
   - Local username/password credentials in a dedicated table.
   - `app_user` remains canonical user record.
   - Accounts created/managed from server CLI.
2. Auth Option B:
   - PeeringDB OAuth flow.
3. Route Server Option A:
   - Worker-driven SSH fanout and BIRD apply workflow.
4. Route Server Option B:
   - Deferred persisted per-route-server state model.

## 2. Traceability Map
1. PRD `F1` maps to phase 3.
2. PRD `F2` maps to phases 3 and 4.
3. PRD `F3` and `F5` map to phase 4.
4. PRD `F4` maps to phase 5.
5. PRD `F6` and `F7` map to phases 3, 4, 5, and 7.
6. Frontend UX/accessibility requirements map to phase 6.
7. Release and operational requirements map to phase 8.
8. Route-server orchestration extension (Route Server Option A) maps to phase 5 and release validation in phase 8.

## 3. Phase 1: Project Bootstrap
Implements: foundational requirements for all PRD features.

Steps:
1. Step 1.1: Initialize Python project layout (`app/`, `tests/`, `alembic/`).
2. Step 1.2: Add dependencies pinned in `TECH_STACK.md`.
3. Step 1.3: Configure lint/type/test tooling (`ruff`, `mypy`, `pytest`).
4. Step 1.4: Add `.env.example` with required secrets, endpoint settings, and `ZT_PROVIDER` config.

Exit criteria:
1. Project starts locally with documented command.
2. Lint/type/test commands run in CI-friendly mode.

Verification:
1. `ruff check .`
2. `mypy .`
3. `pytest -q`

## 4. Phase 2: Data and Migration Foundation
Implements: PRD `F3`, `F4`, `F6` data primitives.

Steps:
1. Step 2.1: Configure SQLAlchemy models for schema in `BACKEND_STRUCTURE.md`.
2. Step 2.2: Initialize Alembic and create initial migration.
3. Step 2.3: Build repository layer for users, ASNs, requests, memberships, and audits.
4. Step 2.4: Add DB tests for uniqueness rules and allowed state transitions.

Exit criteria:
1. Migrations apply cleanly to empty database.
2. Domain invariants are test-covered.

Verification:
1. `alembic upgrade head`
2. `pytest tests/db -q`

## 5. Phase 3: Authentication Integration (Auth Option A + Auth Option B)
Implements: PRD `F1`, part of `F2`, `F6`, `F7`.

Steps:
1. Step 3.1: Keep `/auth/login` with state/nonce/PKCE generation (Auth Option B).
2. Step 3.2: Keep `/auth/callback` token exchange + state/nonce validation (Auth Option B).
3. Step 3.3: Upsert canonical `app_user` and fetch authorized ASN/network context from PeeringDB.
4. Step 3.4: Extend schema for Auth Option A:
   - add `local_credential`
   - add `user_network_access`
   - make `app_user.peeringdb_user_id` nullable while preserving uniqueness when present
5. Step 3.5: Implement local credential repository + password hashing/verification service.
6. Step 3.6: Implement `/auth/local/login` with deterministic auth failures and audit events.
7. Step 3.7: Implement server CLI user provisioning command(s) with options:
   - username/password input mode
   - `--admin` (optional)
   - repeatable ASN assignment
   - repeatable associated-network assignment
8. Step 3.8: Align shared session establishment and logout behavior across both auth modes.
9. Step 3.9: Add tests for:
   - OAuth success/failure callback paths
   - local credential success/failure paths
   - CLI provisioning validation and mutation behavior

Exit criteria:
1. Valid login creates session and user profile for both Auth Option A and Auth Option B.
2. Invalid callback and local-login paths fail safely and audit appropriately.
3. CLI provisioning can create and update local users with admin and ASN/network association options.

Verification:
1. `pytest tests/auth -q`
2. `pytest tests/auth_local -q`
3. `pytest tests/cli -q`
4. Manual checks:
   - `/auth/login -> /auth/callback -> /onboarding`
   - `/auth/local/login -> /onboarding`
   - CLI create local user with and without admin/network options

## 6. Phase 4: Request Workflow
Implements: PRD `F2`, `F3`, `F5`, `F6`.

Steps:
1. Step 4.1: Implement request creation endpoint with ASN ownership and duplicate protections.
2. Step 4.2: Enforce associated-network checks for users with configured `user_network_access`.
3. Step 4.3: Build operator dashboard and request detail pages.
4. Step 4.4: Build admin queue and approve/reject APIs with role checks.
5. Step 4.5: Emit audit events for all workflow state transitions.
6. Step 4.6: Add API and UI tests for transitions, conflict handling, and associated-network authorization failures.

Exit criteria:
1. Operator can submit request and track state.
2. Admin can approve/reject with proper validation and auditing.

Verification:
1. `pytest tests/workflow -q`
2. Manual checks:
   - duplicate request conflict path
   - reject-without-reason validation path
   - associated-network restriction enforcement path

## 7. Phase 5: ZeroTier and Route Server Provisioning (Route Server Option A)
Implements: PRD `F4`, `F5`, `F6`, `F7`.

Steps:
1. Step 5.1: Create provider-agnostic provisioning interface and normalized response model.
2. Step 5.2: Implement `central` adapter using ZeroTier Central API token auth.
3. Step 5.3: Implement `self_hosted_controller` adapter using local controller API and `X-ZT1-Auth`.
4. Step 5.4: Update Celery task to resolve provider from `ZT_PROVIDER`.
5. Step 5.5: Add idempotent membership upsert and safe retry behavior shared across providers.
6. Step 5.6: Persist membership details and expose them in request API.
7. Step 5.7: Add failure handling and admin retry for provider/network/auth errors.
8. Step 5.8: Add unit/integration tests for provider contract, adapter selection, and retry semantics.
9. Step 5.9: Add route-server sync service that fans out to all configured remote route servers over SSH after successful ZeroTier member authorization.
10. Step 5.10: Render explicit per-ASN BIRD peer snippets using ZeroTier-assigned endpoint addresses (one generated peer config per ASN, per route server).
11. Step 5.11: Enforce ROA/RPKI validation in the generated BIRD configuration/policy path used by route-server peers.
12. Step 5.12: Apply BIRD updates safely on each route server (`bird -p`, `birdc configure check`, timed `birdc configure`, confirm/rollback workflow) and capture per-server outcomes.
13. Step 5.13: Transition request to `active` only if all configured route servers apply successfully; otherwise set `failed` with actionable error context and retry path.
14. Step 5.14: Add tests for config rendering, SSH command orchestration, multi-route-server partial failures, and retry idempotency.

Exit criteria:
1. Both provider modes pass shared contract tests.
2. Re-running same provisioning request does not duplicate membership rows.
3. Each approved ASN yields explicit generated BIRD peer config on every configured route server.
4. BIRD route-server policy path used by generated peers includes ROA/RPKI validation.

Verification:
1. `pytest tests/provisioning -q`
2. `pytest tests/route_servers -q`
3. Manual checks:
   - provider selection by `ZT_PROVIDER`
   - admin retry from `failed` state
   - explicit per-ASN peer config rendered and deployed on each route server
   - BIRD validation path confirms ROA/RPKI policy is enabled for generated peers

## 8. Phase 6: Frontend Hardening
Implements: PRD UX clarity and accessibility requirements.

Steps:
1. Step 6.1: Apply styles/components from `FRONTEND_GUIDELINES.md`.
2. Step 6.2: Implement responsive layout behavior for mobile and desktop.
3. Step 6.3: Add accessibility checks (keyboard, focus, contrast, non-color status cues).
4. Step 6.4: Add empty/error states for all critical screens.

Exit criteria:
1. Core routes are usable on mobile and desktop.
2. Accessibility baseline checks pass.

Verification:
1. Manual keyboard-only walkthrough of auth, onboarding, and admin review flows.
2. Automated accessibility check if project tooling is configured.

## 9. Phase 7: Security and Observability
Implements: PRD `F6`, `F7`.

Steps:
1. Step 7.1: Add CSRF protections for all state-changing form actions.
2. Step 7.2: Add structured logging with request IDs and external correlation IDs.
3. Step 7.3: Add metrics for auth success/failure and provisioning latency.
4. Step 7.4: Add security checklist and secret management validation gates.

Exit criteria:
1. State-changing endpoints require CSRF validation.
2. Logs/metrics support traceability across API and worker boundaries.

Verification:
1. `pytest tests/security -q`
2. Manual negative test: CSRF-missing request rejected.

## 10. Phase 8: Release Readiness
Implements: PRD definition-of-done completion.

Steps:
1. Step 8.1: Create deployment manifests and environment docs.
2. Step 8.2: Execute end-to-end staging test using sandbox credentials.
3. Step 8.3: Produce incident response and manual retry runbook (including route-server SSH/BIRD rollback procedures).
4. Step 8.4: Tag `v0.1.0` when PRD acceptance criteria are fully met.

Exit criteria:
1. Staging walkthrough covers operator, admin, and retry paths.
2. Runbook and deployment docs are reviewed and current.

Verification:
1. E2E staging checklist signed off.
2. Final regression test pass before release tag.

## 11. TODO: Phase 9 (Route Server Option B) - Persisted Route Server State Model
Status: deferred until after Phase 8 completion.

Steps:
1. Step 9.1: Add persistent route-server inventory and per-request per-server sync tables/migrations.
2. Step 9.2: Split route-server fanout into one queue job per route server with isolated retries and backoff.
3. Step 9.3: Add reconciliation worker that compares desired state to BIRD effective state and repairs drift.
4. Step 9.4: Expose per-route-server sync state and last error in admin request detail views.
5. Step 9.5: Add tests for partial-failure convergence and per-server retry safety.

Exit criteria:
1. Per-route-server sync status is first-class persisted state, not audit metadata only.
2. Partial route-server failures are independently visible and retryable without replaying all successful servers.

Verification:
1. `pytest tests/route_server_state -q`
2. Manual check: one-route-server-down scenario converges after targeted retry.
