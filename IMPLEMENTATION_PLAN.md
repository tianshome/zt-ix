# Implementation Plan
Version: 1.1
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## 0. Checklist Conventions
- `[x]` complete and verified.
- `[ ]` open and not yet implemented.
- `[ ]` + `Blocked by` + `Reason` marks an explicitly blocked gap that must be revisited when the dependency is complete.

## 0.1 Current Status Snapshot (through Phase 6 + planning update for Phase 8)
- [x] Phase 1 bootstrap is complete.
- [x] Phase 2 data/migration foundation is complete.
- [x] Phase 3 auth integration (Auth Option A + Auth Option B) is complete for automated coverage.
- [x] Phase 4 backend request workflow is complete for API + JSON route responses.
- [x] Phase 5 provider foundation and membership provisioning is complete (Step 5.1 to Step 5.8).
- [x] Phase 6 route-server desired config generation is complete (Step 6.1 to Step 6.3).
- [ ] Configurable auto-approval mode is planned but not implemented.
  - Blocked by: Phase 4 Step 4.7.
  - Reason: approval-mode policy evaluator behavior and guardrails are not implemented yet.
- [x] Queue placeholder has been replaced with real async dispatch.
- [ ] UI/template integration for onboarding/dashboard/request/admin flows.
  - Blocked by: Phase 9 Step 9.1 to Step 9.4.
  - Reason: current accepted scope uses JSON responses; frontend component/styling integration is deferred by plan.
- [ ] Route-server integration (Route Server Option A).
  - Blocked by: Phase 7 implementation.
  - Reason: route-server apply/convergence logic has not been implemented yet.
- [ ] Self-hosted controller lifecycle ownership.
  - Blocked by: Phase 8 implementation.
  - Reason: bootstrap, network reconciliation, token lifecycle, and backup/restore flows are not implemented yet.

## 1. Planning Assumptions and Open Questions
- [x] Assumption: manual admin approval is the default decision control.
- [x] Assumption: provider mode is selected by `ZT_PROVIDER` and cannot be switched per-request.
- [x] Assumption: release environments run `ZT_PROVIDER=self_hosted_controller`; `central` remains compatibility-only for migration/testing and is not a release gate.
- [x] Assumption: local development uses Docker Compose for PostgreSQL/Redis and `uv run` for API/worker/tests.
- [x] Assumption: authentication planning uses Auth Option A (local credentials) and Auth Option B (PeeringDB OAuth).
- [x] Assumption: route-server automation in this plan follows Route Server Option A (worker-driven SSH orchestration).
- [x] Requirement: each approved ASN must produce explicit generated BIRD peer config on every configured route server.
- [x] Requirement: generated BIRD policy path must enable ROA/RPKI validation for route acceptance decisions.
- [x] Requirement: policy auto-approval is a configurable option, with manual admin approval remaining the default mode.
- [ ] Open question: exact auto-approval policy guardrails (eligibility checks, fallback behavior, and rate-limit posture) still need product/security sign-off.
- [ ] Open question: target retry limits/backoff constants should be finalized before phase 5 implementation.
- [ ] Open question: self-hosted controller runtime topology (single-node vs HA pair) for v0.1.0 should be finalized before Phase 8 implementation starts.
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
- [x] PRD `F4` maps to phases 5, 6, and 7.
- [x] PRD `F9` maps to phase 8 and phase 11 release gates.
- [x] PRD `F6` and `F7` map to phases 3, 4, 5, 6, 7, 8, and 10.
- [x] Frontend UX/accessibility requirements map to phase 9.
- [x] Release and operational requirements map to phase 11.
- [x] Route-server orchestration extension (Route Server Option A) maps to phases 6, 7, and 11 validation.

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
- [ ] Step 4.7: Add configurable approval mode support:
  - `manual_admin` (default): keep current admin decision path.
  - `policy_auto`: auto-transition policy-eligible `pending` requests to `approved` with explicit audit metadata.
  - Blocked by: Section 1 open question on auto-approval guardrails and policy rules.
  - Reason: product/security sign-off and policy evaluator implementation are pending.
- [x] Queueing placeholder retained for defer-to-phase-5 behavior (`_enqueue_provisioning_attempt`).
- [x] Replace queueing placeholder with real Celery task dispatch.
- [ ] Integrate rendered UI/templates for workflow pages (Jinja2/HTMX/Alpine).
  - Blocked by: Phase 9 Step 9.1 to Step 9.4.
  - Reason: JSON responses are accepted for the current state; frontend integration is intentionally deferred.

Exit criteria:
- [x] Operator can submit request and track state via API and JSON route responses.
- [x] Admin can approve/reject/retry with proper validation and auditing.
- [ ] Approval mode is configurable (`manual_admin` default, `policy_auto` optional) with auditable decision outcomes.
  - Blocked by: Step 4.7.
  - Reason: policy evaluation path is not implemented yet.
- [x] Admin approval/retry triggers async provisioning dispatch.
- [ ] Operator/admin rendered UI pages match frontend guidelines.
  - Blocked by: Phase 9 Step 9.1 to Step 9.4.
  - Reason: template/UI layer not implemented yet.

Verification:
- [x] `pytest tests/workflow -q`
- [x] Automated checks for duplicate conflict, reject-without-reason, and associated-network restrictions.
- [ ] Automated checks for approval-mode behavior (`manual_admin` and `policy_auto`) and audit emission.
  - Blocked by: Step 4.7.
  - Reason: configurable approval-mode logic is not implemented yet.
- [ ] Manual UI checks for rendered pages.
  - Blocked by: Phase 9 UI implementation is not complete.
  - Reason: current routes are JSON responses by design.

## 7. Phase 5: Provider Foundation and Membership Provisioning
Implements: PRD `F4`, `F5`, `F6`, `F7`.
Goal: complete provider-agnostic ZeroTier member provisioning and request-state handling before route-server apply workflows.

Steps:
- [x] Step 5.1: Create provider-agnostic provisioning interface and normalized response model.
- [x] Step 5.2: Implement `central` adapter using ZeroTier Central API token auth.
- [x] Step 5.3: Implement `self_hosted_controller` adapter using local controller API and `X-ZT1-Auth`.
- [x] Step 5.4: Update Celery task to resolve provider from `ZT_PROVIDER`.
- [x] Step 5.5: Add idempotent membership upsert and safe retry behavior shared across providers.
- [x] Step 5.6: Persist membership details and expose them in request API.
- [x] Step 5.7: Add failure handling and admin retry for provider/network/auth errors.
- [x] Step 5.8: Add unit/integration tests for provider contract, adapter selection, and retry semantics.

Exit criteria:
- [x] Both provider modes pass shared contract tests.
- [x] Re-running the same provisioning request does not duplicate membership rows.
- [x] Provider failures produce actionable `failed` context with admin retry support.

Verification:
- [x] `pytest tests/provisioning -q`
- [ ] Manual checks:
  - provider selection by `ZT_PROVIDER` (self-hosted path required for release)
  - admin retry from `failed` state

## 8. Phase 6: Route Server Desired Config Generation
Implements: PRD `F4`, `F6`, `F8`.
Goal: generate deterministic per-ASN route-server configuration after membership authorization succeeds.

Steps:
- [x] Step 6.1: Add route-server sync service that fans out to all configured remote route servers over SSH after successful ZeroTier member authorization.
- [x] Step 6.2: Render explicit per-ASN BIRD peer snippets using ZeroTier-assigned endpoint addresses.
- [x] Step 6.3: Enforce ROA/RPKI validation in generated BIRD configuration/policy path.

Exit criteria:
- [x] Each approved ASN yields explicit generated BIRD peer config on every configured route server.
- [x] Generated BIRD policy path used by route-server peers includes ROA/RPKI validation.

Verification:
- [x] `pytest tests/route_servers -q`
- [ ] Manual checks:
  - explicit per-ASN peer config rendered and deployed on each route server
  - BIRD validation path confirms ROA/RPKI policy is enabled for generated peers

## 9. Phase 7: Route Server Apply and Convergence
Implements: PRD `F4`, `F6`, `F8`.
Goal: safely apply generated BIRD config to all route servers and converge request state to `active` or `failed`.

Steps:
- [ ] Step 7.1: Apply BIRD updates safely on each route server (`bird -p`, `birdc configure check`, timed `birdc configure`, confirm/rollback workflow) and capture per-server outcomes.
- [ ] Step 7.2: Transition request to `active` only if all configured route servers apply successfully; otherwise set `failed` with actionable error context and retry path.
  - Blocked by: Step 7.1.
  - Reason: convergence logic depends on per-server apply outcomes.
- [ ] Step 7.3: Add tests for config rendering, SSH command orchestration, multi-route-server partial failures, and retry idempotency.
  - Blocked by: Step 7.1 and Step 7.2.
  - Reason: apply/convergence behavior must exist before full route-server failure-mode tests are final.

Exit criteria:
- [ ] Request transitions to `active` only when all configured route servers succeed.
- [ ] Partial route-server failures are captured with retry-safe behavior.

Verification:
- [ ] `pytest tests/route_servers -q`
  - Blocked by: Step 7.1 to Step 7.3.
  - Reason: apply/convergence behavior is not implemented.
- [ ] Manual checks:
  - route-server apply succeeds across all configured servers for a provisioning attempt
  - failed route-server apply captures actionable error context and supports retry idempotency

## 10. Phase 8: Self-Hosted Controller Lifecycle Ownership
Implements: PRD `F4`, `F6`, `F7`, `F9`.
Goal: make the repository responsible for self-hosted controller lifecycle operations required for production ownership.

Steps:
- [ ] Step 8.1: Implement controller runtime bootstrap and readiness workflow.
  - Minimum behaviors:
    - verify controller API reachability/auth at startup,
    - verify controller identity/state prerequisites,
    - fail closed when lifecycle prerequisites are missing.
- [ ] Step 8.2: Implement managed network bootstrap and reconciliation for owned controller mode.
  - Minimum behaviors:
    - create/ensure required ZeroTier network(s) on owned controller,
    - reconcile expected network metadata before provisioning starts.
  - Blocked by: Step 8.1.
  - Reason: network lifecycle operations require validated controller runtime readiness.
- [ ] Step 8.3: Implement controller auth token lifecycle controls.
  - Minimum behaviors:
    - rotate/reload controller auth credentials with deterministic failure handling,
    - emit audit events for token lifecycle actions.
  - Blocked by: Step 8.1.
  - Reason: token lifecycle controls depend on owned-controller bootstrap contract.
- [ ] Step 8.4: Implement controller state backup/restore workflows and verification drill.
  - Minimum behaviors:
    - scheduled backup artifact generation,
    - documented restore path,
    - post-restore validation checks before reopening provisioning.
  - Blocked by: Step 8.1.
  - Reason: backup/restore contract depends on settled controller runtime/state conventions.
- [ ] Step 8.5: Add integration tests for owned lifecycle paths using a real self-hosted controller instance.
  - Minimum coverage:
    - bootstrap success/failure,
    - managed network reconciliation,
    - credential rotation behavior,
    - backup/restore validation path.
  - Blocked by: Step 8.1 to Step 8.4.
  - Reason: lifecycle test targets do not exist until lifecycle implementation is complete.

Exit criteria:
- [ ] Startup and worker flows fail closed when owned-controller lifecycle prerequisites are unmet.
- [ ] Required networks exist and reconcile on the owned controller before request provisioning.
- [ ] Controller token lifecycle and backup/restore paths are auditable and test-backed.
- [ ] Release profile behavior is validated without `ZT_CENTRAL_API_TOKEN` dependency.
  - Blocked by: Phase 11 Step 11.5.
  - Reason: release-gate validation is executed in staging during phase 11.

Verification:
- [ ] `pytest tests/controller_lifecycle -q`
  - Blocked by: Step 8.1 to Step 8.5.
  - Reason: lifecycle test suite does not exist yet.
- [ ] Manual checks:
  - owned-controller bootstrap/readiness checks pass before worker provisioning starts
  - controller backup/restore drill revalidates provisioning readiness

## 11. Phase 9: Frontend Hardening
Implements: PRD UX clarity and accessibility requirements.

Steps:
- [ ] Step 9.1: Apply styles/components from `FRONTEND_GUIDELINES.md`.
- [ ] Step 9.2: Implement responsive layout behavior for mobile and desktop.
- [ ] Step 9.3: Add accessibility checks (keyboard, focus, contrast, non-color status cues).
- [ ] Step 9.4: Add empty/error states for all critical screens.

Blocked items:
- [ ] Integrate real UI for `/onboarding`, `/dashboard`, `/requests/:id`, `/admin/requests`, `/admin/requests/:id`.
  - Blocked by: Phase 9 execution start.
  - Reason: current state intentionally accepts JSON responses; template/UI layer has not started.

Exit criteria:
- [ ] Core routes are usable on mobile and desktop.
- [ ] Accessibility baseline checks pass.

Verification:
- [ ] Manual keyboard-only walkthrough of auth, onboarding, and admin review flows.
- [ ] Automated accessibility check (if tooling is configured).

## 12. Phase 10: Security and Observability
Implements: PRD `F6`, `F7`.

Steps:
- [ ] Step 10.1: Add CSRF protections for all state-changing form actions.
- [ ] Step 10.2: Add structured logging with request IDs and external correlation IDs.
- [ ] Step 10.3: Add metrics for auth success/failure and provisioning latency.
- [ ] Step 10.4: Add security checklist and secret management validation gates.

Exit criteria:
- [ ] State-changing endpoints require CSRF validation.
- [ ] Logs/metrics support traceability across API and worker boundaries.

Verification:
- [ ] `pytest tests/security -q`
- [ ] Manual negative test: CSRF-missing request rejected.

## 13. Phase 11: Release Readiness
Implements: PRD definition-of-done completion.

Steps:
- [ ] Step 11.1: Create deployment manifests and environment docs.
- [ ] Step 11.2: Execute end-to-end staging test using sandbox credentials.
- [ ] Step 11.3: Produce incident response and manual retry runbook (including route-server SSH/BIRD rollback procedures).
- [ ] Step 11.4: Tag `v0.1.0` when PRD acceptance criteria are fully met.
- [ ] Step 11.5: Execute self-hosted-controller-only staging run (no Central credentials) including lifecycle preflight checks.
  - Blocked by: Phase 8 Step 8.1 to Step 8.5.
  - Reason: owned controller lifecycle controls must exist before self-hosted-only staging sign-off.
- [ ] Step 11.6: Execute controller disaster-recovery drill (backup -> restore -> readiness verification -> provisioning resume).
  - Blocked by: Step 11.5.
  - Reason: DR drill sign-off depends on self-hosted-only staging baseline.

Exit criteria:
- [ ] Staging walkthrough covers operator, admin, and retry paths.
- [ ] Runbook and deployment docs are reviewed and current.
- [ ] Staging uses owned self-hosted controller lifecycle paths with no Central-token dependency.
- [ ] Disaster-recovery drill is completed and recorded for release sign-off.

Verification:
- [ ] E2E staging checklist signed off.
- [ ] Final regression test pass before release tag.
- [ ] Self-hosted lifecycle checklist signed off (bootstrap, reconciliation, rotation, backup/restore).

## 14. TODO: Phase 12 (Route Server Option B) - Persisted Route Server State Model
Status: deferred until after Phase 11 completion.

Steps:
- [ ] Step 12.1: Add persistent route-server inventory and per-request per-server sync tables/migrations.
  - Blocked by: Phase 11 completion.
  - Reason: Route Server Option B is explicitly out of active scope before release readiness.
- [ ] Step 12.2: Split route-server fanout into one queue job per route server with isolated retries and backoff.
  - Blocked by: Step 12.1.
  - Reason: per-server jobs require persisted route-server state model.
- [ ] Step 12.3: Add reconciliation worker that compares desired state to BIRD effective state and repairs drift.
  - Blocked by: Step 12.1 and Step 12.2.
  - Reason: reconciliation requires persisted desired/effective per-server state and isolated jobs.
- [ ] Step 12.4: Expose per-route-server sync state and last error in admin request detail views.
  - Blocked by: Step 12.1.
  - Reason: UI/API exposure depends on persisted state model.
- [ ] Step 12.5: Add tests for partial-failure convergence and per-server retry safety.
  - Blocked by: Step 12.1 to Step 12.4.
  - Reason: test targets do not exist until the model/jobs/reconciliation are implemented.

Exit criteria:
- [ ] Per-route-server sync status is first-class persisted state, not audit metadata only.
- [ ] Partial route-server failures are independently visible and retryable without replaying all successful servers.

Verification:
- [ ] `pytest tests/route_server_state -q`
- [ ] Manual check: one-route-server-down scenario converges after targeted retry.
