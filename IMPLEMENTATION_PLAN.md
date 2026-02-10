# Implementation Plan
Version: 0.6
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## 0. Checklist Conventions
- `[x]` complete and verified.
- `[ ]` open and not yet implemented.
- `[ ]` + `Blocked by` + `Reason` marks an explicitly blocked gap that must be revisited when the dependency is complete.

## 0.1 Current Status Snapshot (through Phase 4)
- [x] Phase 1 bootstrap is complete.
- [x] Phase 2 data/migration foundation is complete.
- [x] Phase 3 auth integration (Auth Option A + Auth Option B) is complete for automated coverage.
- [x] Phase 4 backend request workflow is complete for API + JSON route responses.
- [x] Placeholder queue hook exists in admin approve/retry flow (`_enqueue_provisioning_attempt`).
- [ ] Replace queue placeholder with real async dispatch.
  - Blocked by: Phase 5 Step 5.1 to Step 5.4.
  - Reason: queue target, payload contract, and provider-selection behavior are not implemented yet.
- [ ] UI/template integration for onboarding/dashboard/request/admin flows.
  - Blocked by: Phase 6 Step 6.1 to Step 6.4.
  - Reason: current accepted scope uses JSON responses; frontend component/styling integration is deferred by plan.
- [ ] Route-server integration (Route Server Option A).
  - Blocked by: Phase 5 Sub-phase 5A completion (Step 5.1 to Step 5.8).
  - Reason: route-server orchestration depends on finalized provider provisioning flow and stable membership outcomes.

## 1. Planning Assumptions and Open Questions
- [x] Assumption: phase 1 uses admin approval as default decision control.
- [x] Assumption: provider mode is selected by `ZT_PROVIDER` and cannot be switched per-request.
- [x] Assumption: local development uses Docker Compose for PostgreSQL/Redis and `uv run` for API/worker/tests.
- [x] Assumption: authentication planning uses Auth Option A (local credentials) and Auth Option B (PeeringDB OAuth).
- [x] Assumption: route-server automation in this plan follows Route Server Option A (worker-driven SSH orchestration).
- [x] Requirement: each approved ASN must produce explicit generated BIRD peer config on every configured route server.
- [x] Requirement: generated BIRD policy path must enable ROA/RPKI validation for route acceptance decisions.
- [ ] Open question: policy-based auto-approval scope (if any) remains deferred pending product decision.
- [ ] Open question: target retry limits/backoff constants should be finalized before phase 5 implementation.
- [x] Open question resolved: for Auth Option A, empty associated-network assignment means unrestricted access when no rows exist.

## 1.1 Option Labels (Disambiguation)
- [x] Auth Option A:
  - Local username/password credentials in a dedicated table.
  - `app_user` remains canonical user record.
  - Accounts are created/managed from server CLI.
- [x] Auth Option B:
  - PeeringDB OAuth flow.
- [x] Route Server Option A:
  - Worker-driven SSH fanout and BIRD apply workflow.
- [x] Route Server Option B:
  - Deferred persisted per-route-server state model.

## 2. Traceability Map
- [x] PRD `F1` maps to phase 3.
- [x] PRD `F2` maps to phases 3 and 4.
- [x] PRD `F3` and `F5` map to phase 4.
- [x] PRD `F4` maps to phase 5.
- [x] PRD `F6` and `F7` map to phases 3, 4, 5, and 7.
- [x] Frontend UX/accessibility requirements map to phase 6.
- [x] Release and operational requirements map to phase 8.
- [x] Route-server orchestration extension (Route Server Option A) maps to phase 5 and phase 8 validation.

## 3. Phase 1: Project Bootstrap
Implements: foundational requirements for all PRD features.

Steps:
- [x] Step 1.1: Initialize Python project layout (`app/`, `tests/`, `alembic/`).
- [x] Step 1.2: Add dependencies pinned in `TECH_STACK.md`.
- [x] Step 1.3: Configure lint/type/test tooling (`ruff`, `mypy`, `pytest`).
- [x] Step 1.4: Add `.env.example` with required secrets, endpoint settings, and `ZT_PROVIDER` config.

Exit criteria:
- [x] Project starts locally with documented command.
- [x] Lint/type/test commands run in CI-friendly mode.

Verification:
- [x] `ruff check .`
- [x] `mypy .`
- [x] `pytest -q`

## 4. Phase 2: Data and Migration Foundation
Implements: PRD `F3`, `F4`, `F6` data primitives.

Steps:
- [x] Step 2.1: Configure SQLAlchemy models for schema in `BACKEND_STRUCTURE.md`.
- [x] Step 2.2: Initialize Alembic and create initial migration.
- [x] Step 2.3: Build repository layer for users, ASNs, requests, memberships, and audits.
- [x] Step 2.4: Add DB tests for uniqueness rules and allowed state transitions.

Exit criteria:
- [x] Migrations apply cleanly to empty database.
- [x] Domain invariants are test-covered.

Verification:
- [x] `alembic upgrade head`
- [x] `pytest tests/db -q`

## 5. Phase 3: Authentication Integration (Auth Option A + Auth Option B)
Implements: PRD `F1`, part of `F2`, `F6`, `F7`.

Steps:
- [x] Step 3.1: Keep `/auth/login` with state/nonce/PKCE generation (Auth Option B).
- [x] Step 3.2: Keep `/auth/callback` token exchange + state/nonce validation (Auth Option B).
- [x] Step 3.3: Upsert canonical `app_user` and fetch authorized ASN/network context from PeeringDB.
- [x] Step 3.4: Extend schema for Auth Option A:
  - add `local_credential`
  - add `user_network_access`
  - make `app_user.peeringdb_user_id` nullable while preserving uniqueness when present
- [x] Step 3.5: Implement local credential repository + password hashing/verification service.
- [x] Step 3.6: Implement `/auth/local/login` with deterministic auth failures and audit events.
- [x] Step 3.7: Implement server CLI user provisioning command(s) with options:
  - username/password input mode
  - `--admin` (optional)
  - repeatable ASN assignment
  - repeatable associated-network assignment
- [x] Step 3.8: Align shared session establishment and logout behavior across both auth modes.
- [x] Step 3.9: Add tests for:
  - OAuth success/failure callback paths
  - local credential success/failure paths
  - CLI provisioning validation and mutation behavior

Exit criteria:
- [x] Valid login creates session and user profile for both Auth Option A and Auth Option B.
- [x] Invalid callback and local-login paths fail safely and audit appropriately.
- [x] CLI provisioning can create and update local users with admin and ASN/network association options.

Verification:
- [x] `pytest tests/auth -q`
- [x] `pytest tests/auth_local -q`
- [x] `pytest tests/cli -q`
- [ ] Manual browser checks against live PeeringDB app.
  - Blocked by: external browser + live OAuth credentials not available in this execution environment.
  - Reason: this environment supports automated tests only.

## 6. Phase 4: Request Workflow
Implements: PRD `F2`, `F3`, `F5`, `F6`.

Steps:
- [x] Step 4.1: Implement request creation endpoint with ASN ownership and duplicate protections.
- [x] Step 4.2: Enforce associated-network checks for users with configured `user_network_access`.
- [x] Step 4.3: Build operator dashboard and request detail route handlers (current response mode: JSON payloads).
- [x] Step 4.4: Build admin queue/detail and approve/reject/retry APIs with role checks.
- [x] Step 4.5: Emit audit events for all workflow state transitions.
- [x] Step 4.6: Add API and JSON-route tests for transitions, conflict handling, and associated-network authorization failures.
- [x] Queueing placeholder retained for defer-to-phase-5 behavior (`_enqueue_provisioning_attempt`).
- [ ] Replace queueing placeholder with real Celery task dispatch.
  - Blocked by: Phase 5 Step 5.1 to Step 5.4.
  - Reason: provider interface + adapter selection + worker dispatch contract are not implemented yet.
- [ ] Integrate rendered UI/templates for workflow pages (Jinja2/HTMX/Alpine).
  - Blocked by: Phase 6 Step 6.1 to Step 6.4.
  - Reason: JSON responses are accepted for the current state; frontend integration is intentionally deferred.

Exit criteria:
- [x] Operator can submit request and track state via API and JSON route responses.
- [x] Admin can approve/reject/retry with proper validation and auditing.
- [ ] Admin approval/retry triggers async provisioning dispatch.
  - Blocked by: Phase 5 Step 5.4.
  - Reason: Celery/provider wiring not implemented yet.
- [ ] Operator/admin rendered UI pages match frontend guidelines.
  - Blocked by: Phase 6 Step 6.1 to Step 6.4.
  - Reason: template/UI layer not implemented yet.

Verification:
- [x] `pytest tests/workflow -q`
- [x] Automated checks for duplicate conflict, reject-without-reason, and associated-network restrictions.
- [ ] Manual UI checks for rendered pages.
  - Blocked by: Phase 6 UI implementation is not complete.
  - Reason: current routes are JSON responses by design.

## 7. Phase 5: ZeroTier and Route Server Provisioning (Route Server Option A)
Implements: PRD `F4`, `F5`, `F6`, `F7`.

### 7.1 Sub-phase 5A: Provider Foundation and Membership Provisioning
Goal: complete provider-agnostic ZeroTier member provisioning and request-state handling before any route-server actions.

Steps:
- [ ] Step 5.1: Create provider-agnostic provisioning interface and normalized response model.
- [ ] Step 5.2: Implement `central` adapter using ZeroTier Central API token auth.
- [ ] Step 5.3: Implement `self_hosted_controller` adapter using local controller API and `X-ZT1-Auth`.
- [ ] Step 5.4: Update Celery task to resolve provider from `ZT_PROVIDER`.
- [ ] Step 5.5: Add idempotent membership upsert and safe retry behavior shared across providers.
- [ ] Step 5.6: Persist membership details and expose them in request API.
- [ ] Step 5.7: Add failure handling and admin retry for provider/network/auth errors.
- [ ] Step 5.8: Add unit/integration tests for provider contract, adapter selection, and retry semantics.

Self-contained outcomes:
- [ ] Both provider modes pass shared contract tests.
- [ ] Re-running the same provisioning request does not duplicate membership rows.
- [ ] Provider failures produce actionable `failed` context with admin retry support.

### 7.2 Sub-phase 5B: Route Server Desired Config Generation
Goal: generate deterministic per-ASN route-server configuration only after membership authorization succeeds.

Steps:
- [ ] Step 5.9: Add route-server sync service that fans out to all configured remote route servers over SSH after successful ZeroTier member authorization.
  - Blocked by: Step 5.1 to Step 5.8.
  - Reason: route-server sync requires stable provider/membership outputs and finalized provisioning failure semantics.
- [ ] Step 5.10: Render explicit per-ASN BIRD peer snippets using ZeroTier-assigned endpoint addresses.
  - Blocked by: Step 5.1 to Step 5.9.
  - Reason: rendering inputs depend on completed provisioning flow and route-server sync orchestration service.
- [ ] Step 5.11: Enforce ROA/RPKI validation in generated BIRD configuration/policy path.
  - Blocked by: Step 5.10.
  - Reason: policy enforcement is part of the generated config artifacts produced by the renderer.

Self-contained outcomes:
- [ ] Each approved ASN yields explicit generated BIRD peer config on every configured route server.
- [ ] Generated BIRD policy path used by route-server peers includes ROA/RPKI validation.

### 7.3 Sub-phase 5C: Route Server Apply and Convergence
Goal: safely apply generated BIRD config to all route servers and converge request state to `active` or `failed`.

Steps:
- [ ] Step 5.12: Apply BIRD updates safely on each route server (`bird -p`, `birdc configure check`, timed `birdc configure`, confirm/rollback workflow) and capture per-server outcomes.
  - Blocked by: Step 5.9 to Step 5.11.
  - Reason: apply workflow requires completed fanout/orchestration + generated config artifacts.
- [ ] Step 5.13: Transition request to `active` only if all configured route servers apply successfully; otherwise set `failed` with actionable error context and retry path.
  - Blocked by: Step 5.12.
  - Reason: convergence logic depends on per-server apply outcomes.
- [ ] Step 5.14: Add tests for config rendering, SSH command orchestration, multi-route-server partial failures, and retry idempotency.
  - Blocked by: Step 5.9 to Step 5.13.
  - Reason: test coverage depends on implemented renderer/orchestration/apply paths.

Self-contained outcomes:
- [ ] Request transitions to `active` only when all configured route servers succeed.
- [ ] Partial route-server failures are captured with retry-safe behavior.

Phase 5 overall exit criteria:
- [ ] Both provider modes pass shared contract tests.
- [ ] Re-running same provisioning request does not duplicate membership rows.
- [ ] Each approved ASN yields explicit generated BIRD peer config on every configured route server.
- [ ] BIRD route-server policy path used by generated peers includes ROA/RPKI validation.

Verification:
- [ ] `pytest tests/provisioning -q`
- [ ] `pytest tests/route_servers -q`
- [ ] Manual checks:
  - provider selection by `ZT_PROVIDER`
  - admin retry from `failed` state
  - explicit per-ASN peer config rendered and deployed on each route server
  - BIRD validation path confirms ROA/RPKI policy is enabled for generated peers

## 8. Phase 6: Frontend Hardening
Implements: PRD UX clarity and accessibility requirements.

Steps:
- [ ] Step 6.1: Apply styles/components from `FRONTEND_GUIDELINES.md`.
- [ ] Step 6.2: Implement responsive layout behavior for mobile and desktop.
- [ ] Step 6.3: Add accessibility checks (keyboard, focus, contrast, non-color status cues).
- [ ] Step 6.4: Add empty/error states for all critical screens.

Blocked items:
- [ ] Integrate real UI for `/onboarding`, `/dashboard`, `/requests/:id`, `/admin/requests`, `/admin/requests/:id`.
  - Blocked by: Phase 6 execution start.
  - Reason: current state intentionally accepts JSON responses; template/UI layer has not started.

Exit criteria:
- [ ] Core routes are usable on mobile and desktop.
- [ ] Accessibility baseline checks pass.

Verification:
- [ ] Manual keyboard-only walkthrough of auth, onboarding, and admin review flows.
- [ ] Automated accessibility check (if tooling is configured).

## 9. Phase 7: Security and Observability
Implements: PRD `F6`, `F7`.

Steps:
- [ ] Step 7.1: Add CSRF protections for all state-changing form actions.
- [ ] Step 7.2: Add structured logging with request IDs and external correlation IDs.
- [ ] Step 7.3: Add metrics for auth success/failure and provisioning latency.
- [ ] Step 7.4: Add security checklist and secret management validation gates.

Exit criteria:
- [ ] State-changing endpoints require CSRF validation.
- [ ] Logs/metrics support traceability across API and worker boundaries.

Verification:
- [ ] `pytest tests/security -q`
- [ ] Manual negative test: CSRF-missing request rejected.

## 10. Phase 8: Release Readiness
Implements: PRD definition-of-done completion.

Steps:
- [ ] Step 8.1: Create deployment manifests and environment docs.
- [ ] Step 8.2: Execute end-to-end staging test using sandbox credentials.
- [ ] Step 8.3: Produce incident response and manual retry runbook (including route-server SSH/BIRD rollback procedures).
- [ ] Step 8.4: Tag `v0.1.0` when PRD acceptance criteria are fully met.

Exit criteria:
- [ ] Staging walkthrough covers operator, admin, and retry paths.
- [ ] Runbook and deployment docs are reviewed and current.

Verification:
- [ ] E2E staging checklist signed off.
- [ ] Final regression test pass before release tag.

## 11. TODO: Phase 9 (Route Server Option B) - Persisted Route Server State Model
Status: deferred until after Phase 8 completion.

Steps:
- [ ] Step 9.1: Add persistent route-server inventory and per-request per-server sync tables/migrations.
  - Blocked by: Phase 8 completion.
  - Reason: Route Server Option B is explicitly out of active scope before release readiness.
- [ ] Step 9.2: Split route-server fanout into one queue job per route server with isolated retries and backoff.
  - Blocked by: Step 9.1.
  - Reason: per-server jobs require persisted route-server state model.
- [ ] Step 9.3: Add reconciliation worker that compares desired state to BIRD effective state and repairs drift.
  - Blocked by: Step 9.1 and Step 9.2.
  - Reason: reconciliation requires persisted desired/effective per-server state and isolated jobs.
- [ ] Step 9.4: Expose per-route-server sync state and last error in admin request detail views.
  - Blocked by: Step 9.1.
  - Reason: UI/API exposure depends on persisted state model.
- [ ] Step 9.5: Add tests for partial-failure convergence and per-server retry safety.
  - Blocked by: Step 9.1 to Step 9.4.
  - Reason: test targets do not exist until the model/jobs/reconciliation are implemented.

Exit criteria:
- [ ] Per-route-server sync status is first-class persisted state, not audit metadata only.
- [ ] Partial route-server failures are independently visible and retryable without replaying all successful servers.

Verification:
- [ ] `pytest tests/route_server_state -q`
- [ ] Manual check: one-route-server-down scenario converges after targeted retry.
