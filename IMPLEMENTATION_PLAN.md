# Implementation Plan
Version: 1.8
Date: 2026-02-11

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## 0. Checklist Conventions
- `[x]` complete and verified.
- `[ ]` open and not yet implemented.
- `[ ]` + `Blocked by` + `Reason` marks an explicitly blocked gap that must be revisited when the dependency is complete.

## 0.1 Current Status Snapshot (through Phase 8 implementation)
- [x] Phase 1 bootstrap is complete.
- [x] Phase 2 data/migration foundation is complete.
- [x] Phase 3 auth integration (Auth Option A + Auth Option B) is complete for automated coverage.
- [x] Phase 4 backend request workflow is complete for API + JSON route responses.
- [x] Phase 5 provider foundation and membership provisioning is complete (Step 5.1 to Step 5.8).
- [x] Phase 6 route-server desired config generation is complete (Step 6.1 to Step 6.3).
- [ ] Configurable approval mode is planned but not implemented.
  - Blocked by: Phase 9 Step 9.4 to Step 9.5.
  - Reason: runtime-config approval-mode wiring and `policy_auto` transition behavior are not implemented yet.
- [x] Queue placeholder has been replaced with real async dispatch.
- [ ] SPA frontend integration for onboarding/dashboard/request/admin flows.
  - Blocked by: Phase 10 Step 10.1 to Step 10.5 and Phase 11 Step 11.1 to Step 11.6.
  - Reason: SPA runtime foundation and core workflow screens are not implemented yet.
- [x] Route-server integration (Route Server Option A) is complete (Phase 7 Step 7.1 to Step 7.3).
- [x] Self-hosted controller lifecycle ownership is implemented for planned scope (Phase 8 Step 8.1 to Step 8.5).

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
- [x] Requirement: approval mode must be defined in `runtime-config.yaml` (`workflow.approval_mode`).
- [x] Scope decision: detailed `policy_auto` guardrail expansion is out of scope for `v0.1.0`; request eligibility relies on existing PeeringDB/local ASN/network authorization checks.
- [x] Assumption: frontend runtime is strict SPA with client-side route ownership and API-only backend interactions.
- [x] Assumption: Phase 8 lifecycle ownership targets a single self-hosted controller for `v0.1.0`; HA pair/topology orchestration is post-`v0.1.0` hardening and not a Phase 8 blocker.
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
- [x] PRD `F9` maps to phase 8 and phase 14 release gates.
- [x] PRD `F6` and `F7` map to phases 3, 4, 5, 6, 7, 8, and 13.
- [x] SPA delivery and frontend UX requirements map to phases 9, 10, 11, and 12.
- [x] Accessibility/i18n hardening beyond MVP is deferred post-`v0.1.0`.
- [x] Release and operational requirements map to phase 14.
- [x] Route-server orchestration extension (Route Server Option A) maps to phases 6, 7, and 14 validation.

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
  - Blocked by: Phase 9 Step 9.4 to Step 9.5.
  - Reason: runtime-config approval-mode wiring and SPA/API realignment work are scheduled in phase 9.
- [x] Queueing placeholder retained for defer-to-phase-5 behavior (`_enqueue_provisioning_attempt`).
- [x] Replace queueing placeholder with real Celery task dispatch.
- [ ] Integrate React/TypeScript/shadcn-ui frontend workflow pages for operator/admin routes.
  - Blocked by: Phase 10 Step 10.1 to Step 10.5 and Phase 11 Step 11.1 to Step 11.6.
  - Reason: SPA runtime foundation and workflow UI implementation are intentionally deferred to dedicated frontend phases.

Exit criteria:
- [x] Operator can submit request and track state via API and JSON route responses.
- [x] Admin can approve/reject/retry with proper validation and auditing.
- [ ] Approval mode is configurable (`manual_admin` default, `policy_auto` optional) with auditable decision outcomes.
  - Blocked by: Step 4.7.
  - Reason: policy evaluation path is not implemented yet.
- [x] Admin approval/retry triggers async provisioning dispatch.
- [ ] Operator/admin rendered UI pages match frontend guidelines.
  - Blocked by: Phase 10 Step 10.1 to Step 10.5 and Phase 11 Step 11.1 to Step 11.6.
  - Reason: SPA frontend layer is not implemented yet.

Verification:
- [x] `pytest tests/workflow -q`
- [x] Automated checks for duplicate conflict, reject-without-reason, and associated-network restrictions.
- [ ] Automated checks for approval-mode behavior (`manual_admin` and `policy_auto`) and audit emission.
  - Blocked by: Step 4.7.
  - Reason: configurable approval-mode logic is not implemented yet.
- [ ] Manual UI checks for rendered pages.
  - Blocked by: Phase 11 Step 11.1 to Step 11.6.
  - Reason: SPA workflow screens are not implemented yet.

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
- [x] Step 7.1: Apply BIRD updates safely on each route server (`bird -p`, `birdc configure check`, timed `birdc configure`, confirm/rollback workflow) and capture per-server outcomes.
- [x] Step 7.2: Transition request to `active` only if all configured route servers apply successfully; otherwise set `failed` with actionable error context and retry path.
- [x] Step 7.3: Add tests for config rendering, SSH command orchestration, multi-route-server partial failures, and retry idempotency.

Exit criteria:
- [x] Request transitions to `active` only when all configured route servers succeed.
- [x] Partial route-server failures are captured with retry-safe behavior.

Verification:
- [x] `pytest tests/route_servers -q`
- [x] `pytest tests/provisioning/test_service.py -q`
- [x] `ZTIX_RUN_ROUTE_SERVER_INTEGRATION=1 uv run pytest tests/route_servers/test_live_integration.py -q -k live_route_server_creates_test_bgp_session`
- [x] Manual check: route-server apply succeeds across all configured servers for a provisioning attempt.
- [x] Manual check: failed route-server apply captures actionable error context and supports retry idempotency.

## 10. Phase 8: Self-Hosted ZeroTier Controller Lifecycle Ownership
Implements: PRD `F4`, `F6`, `F7`, `F9`.
Goal: implement minimum viable lifecycle ownership for self-hosted controller operation in release environments, without ZeroTier Central feature parity.

Scope boundaries:
- In scope: readiness/auth gating, required-network reconciliation, token reload control, backup/restore validation drill, and lifecycle audit events.
- Out of scope: ZeroTier Central feature parity, Central org/user/team workflows, billing workflows, and custom roots/planet orchestration.

Steps:
- [x] Step 8.0: Add containerized owned-controller runtime for lifecycle validation.
  - Minimum behaviors:
    - add `zerotier-controller` service to `docker-compose.yml` using `zerotier/zerotier:1.14.2`,
    - persist `/var/lib/zerotier-one` as a named volume so controller identity and state survive restarts,
    - expose controller API on `127.0.0.1:9993/tcp` and controller transport on `9993/udp` while running alongside `postgres` and `redis`,
    - provide controller `local.conf` with `settings.allowManagementFrom` configured for host-originated management probes in compose topology,
    - document bootstrap sequence to run all dependency containers together and source `ZT_CONTROLLER_AUTH_TOKEN` from controller secret material (`/var/lib/zerotier-one/authtoken.secret`) or managed runtime secret.
- [x] Step 8.1: Implement controller runtime bootstrap and readiness gate.
  - Minimum behaviors:
    - verify controller service reachability and auth before provisioning (`/status`, `/controller` probes),
    - fail closed in worker provisioning flow when lifecycle prerequisites are unmet,
    - emit auditable readiness outcomes with deterministic remediation metadata.
- [x] Step 8.2: Implement managed network bootstrap and reconciliation for owned controller mode.
  - Minimum behaviors:
    - reconcile required network IDs from `ZT_CONTROLLER_REQUIRED_NETWORK_IDS`,
    - validate/create required controller networks before provisioning begins,
    - fail closed when reconciliation cannot converge.
- [x] Step 8.3: Implement controller auth token lifecycle controls.
  - Minimum behaviors:
    - support controlled token reload from runtime secret source,
    - re-run readiness gate immediately after token reload,
    - keep provisioning blocked on token/auth validation failure and emit lifecycle audit events.
- [x] Step 8.4: Implement controller state backup/restore workflows and verification drill.
  - Minimum behaviors:
    - backup controller state artifacts (`controller.d` plus controller identity files) to `ZT_CONTROLLER_BACKUP_DIR`,
    - enforce retention policy from `ZT_CONTROLLER_BACKUP_RETENTION_COUNT`,
    - define restore validation drill that must pass readiness + network reconciliation before provisioning resumes.
- [x] Step 8.5: Add lifecycle-focused automated tests and manual drill checklist.
  - Minimum coverage:
    - readiness success/failure gating behavior,
    - required-network reconciliation convergence/failure behavior,
    - token reload success/failure behavior,
    - backup retention and restore validation gating behavior.

Exit criteria:
- [x] `zerotier/zerotier:1.14.2` controller runs on `9993` (TCP API + UDP transport) in the same compose stack as `postgres` and `redis`.
- [x] Startup and worker provisioning paths fail closed when self-hosted lifecycle readiness is unhealthy.
- [x] Required controller networks reconcile before member authorization attempts run.
- [x] Token reload control and backup/restore validation drill are auditable and test-backed.
- [ ] Release profile behavior is validated without `ZT_CENTRAL_API_TOKEN` dependency.
  - Blocked by: Phase 14 Step 14.5.
  - Reason: release-gate validation is executed in staging during phase 14.

Verification:
- [x] `POSTGRES_HOST_PORT=55433 docker compose up -d postgres redis zerotier-controller`
- [x] `POSTGRES_HOST_PORT=55433 docker compose ps postgres redis zerotier-controller`
- [x] `curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/status`
- [x] `POSTGRES_HOST_PORT=55433 docker compose exec -T zerotier-controller sh -lc 'TOKEN="$(cat /var/lib/zerotier-one/authtoken.secret)"; curl -fsS -H "X-ZT1-Auth: ${TOKEN}" http://127.0.0.1:9993/status'`
- [x] `curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/controller`
- [x] `curl -fsS -H "X-ZT1-Auth: ${ZT_CONTROLLER_AUTH_TOKEN}" http://127.0.0.1:9993/controller/network`
- [x] `DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:55433/zt_ix ZT_PROVIDER=self_hosted_controller ... uv run python -m app.cli.controller_lifecycle preflight`
- [x] `pytest tests/controller_lifecycle -q`
- [x] `pytest tests/provisioning -q -k lifecycle`
- [ ] Manual checks:
  - controller container starts healthy with `postgres` and `redis` in the same compose run
  - readiness gate blocks provisioning while controller auth/probes fail
  - required-network reconciliation completes before provisioning resumes
  - backup -> restore drill revalidates readiness and reconciliation before reopening provisioning

## 11. Phase 9: API Realignment for SPA and Approval-Mode Config
Implements: PRD `F1`, `F2`, `F3`, `F5`, SPA/API contract decisions.
Goal: provide complete JSON API surface for SPA and remove redirect/page assumptions from backend workflows before frontend implementation starts.

Steps:
- [ ] Step 9.1: Add SPA auth APIs:
  - `POST /api/v1/auth/peeringdb/start`
  - `POST /api/v1/auth/peeringdb/callback`
  - `POST /api/v1/auth/local/login`
  - `POST /api/v1/auth/logout`
- [ ] Step 9.2: Add SPA workflow data APIs:
  - `GET /api/v1/onboarding/context`
  - `GET /api/v1/admin/requests`
  - `GET /api/v1/admin/requests/{request_id}`
- [ ] Step 9.3: Remove backend `/error` page contract and backend workflow page-route dependence for SPA flows.
- [ ] Step 9.4: Parse `workflow.approval_mode` from `runtime-config.yaml` (`manual_admin` default, `policy_auto` optional).
- [ ] Step 9.5: Implement approval-mode behavior with current validation scope:
  - keep existing ASN/network eligibility checks as authoritative,
  - do not add additional policy guardrails in `v0.1.0`,
  - emit explicit audit metadata for auto-approved decisions.
- [ ] Step 9.6: Add/adjust automated tests for JSON auth callbacks, onboarding context, admin list/detail APIs, and approval-mode behavior.
- [ ] Step 9.7: Remove legacy redirect-style auth routes and compatibility behavior and clean up FastAPI-related modules.

Exit criteria:
- [ ] SPA-required auth/workflow/admin APIs exist and are test-covered.
- [ ] Approval mode is runtime-configurable from `runtime-config.yaml`.
- [ ] Backend no longer relies on server error page redirects for user-facing auth errors.

Verification:
- [ ] `pytest tests/auth -q`
- [ ] `pytest tests/auth_local -q`
- [ ] `pytest tests/workflow -q`
- [ ] Approval-mode tests cover `manual_admin` and `policy_auto` outcomes.

## 12. Phase 10: SPA Platform and Delivery Topology
Implements: PRD SPA runtime scope and frontend stack requirements.
Goal: establish SPA build/runtime foundation after backend API realignment is complete.

Steps:
- [ ] Step 10.1: Bootstrap frontend workspace (`frontend/`) using pinned React/TypeScript/Vite/npm versions from `TECH_STACK.md`.
- [ ] Step 10.2: Implement client-side router and shared app shell for `/`, `/login`, `/auth/callback`, `/onboarding`, `/dashboard`, `/requests/:id`, `/admin/requests`, `/admin/requests/:id`.
- [ ] Step 10.3: Add production NGINX web container assets/config for SPA static serving and `/api/*` reverse proxy to FastAPI service container.
- [ ] Step 10.4: Update `docker-compose.yml` for production-like profile with separate `web` and `api` services.
- [ ] Step 10.5: Add Vite dev proxy config and local SPA run instructions (`vite serve` -> `localhost:8000` API proxy).

Exit criteria:
- [ ] SPA router owns browser routes.
- [ ] Production compose profile documents NGINX web container + API container topology.
- [ ] Local development can run SPA via Vite proxy without backend template routes.

Verification:
- [ ] `npm ci` (inside `frontend/`)
- [ ] `npm run build` (inside `frontend/`)
- [ ] `docker compose config` shows `web` -> `api` topology wiring.

## 13. Phase 11: Core SPA Workflow Screens (MVP)
Implements: PRD operator/admin UI scope for `v0.1.0`.
Goal: deliver functional SPA workflows using API polling and MVP table behavior.

Steps:
- [ ] Step 11.1: Implement `/login` and `/auth/callback` screens with inline auth errors (no backend error-page redirects).
- [ ] Step 11.2: Implement `/onboarding` request form with duplicate-conflict and eligibility error handling.
- [ ] Step 11.3: Implement operator pages (`/dashboard`, `/requests/:id`) using GET polling for request status refresh.
- [ ] Step 11.4: Implement admin pages (`/admin/requests`, `/admin/requests/:id`) with approve/reject/retry actions.
- [ ] Step 11.5: Use shadcn/Radix data-table primitives for admin/operator tables with MVP behavior only.
- [ ] Step 11.6: Add minimum viable empty/error states for critical screens.

Blocked items:
- [ ] Large-scale table optimization (virtualization, advanced sort persistence, server-driven pagination tuning).
  - Blocked by: Post-`v0.1.0` frontend hardening phase.
  - Reason: explicitly out of MVP scope.
- [ ] Enhanced audit-event timeline UX and formatting.
  - Blocked by: Post-`v0.1.0` frontend hardening phase.
  - Reason: explicitly deferred by current product scope.
- [ ] Mobile-specific admin layout optimization beyond baseline responsive table behavior.
  - Blocked by: Post-`v0.1.0` frontend hardening phase.
  - Reason: current scope accepts shadcn/Radix default mobile behavior.

Exit criteria:
- [ ] Login/onboarding/operator/admin SPA routes are usable end-to-end with backend APIs.
- [ ] Status updates are visible via HTTP polling without manual page reloads.
- [ ] Core request/admin actions are available from SPA screens.

Verification:
- [ ] Manual SPA walkthrough for auth -> onboarding -> request detail -> admin decision/retry.
- [ ] Manual polling check confirms status transition visibility without full page refresh.

## 14. Phase 12: Frontend MVP Validation and Deferred UX Scope
Implements: final frontend quality gate for `v0.1.0`.
Goal: validate shipped SPA behavior while explicitly tracking deferred frontend quality work.

Steps:
- [ ] Step 12.1: Add frontend/API integration smoke tests for login, request creation, admin decision, and retry flows.
- [ ] Step 12.2: Validate MVP responsive behavior on target breakpoints (`sm`, `md`, `lg`) for onboarding/dashboard/admin queue screens.
- [ ] Step 12.3: Document deferred frontend scope items (full accessibility hardening, i18n, advanced mobile/table optimization) in release checklist.

Blocked items:
- [ ] Automated accessibility tooling gate for CI.
  - Blocked by: Post-`v0.1.0` frontend hardening phase.
  - Reason: accessibility automation is explicitly deferred beyond `v0.1.0`.
- [ ] Internationalized error/status message catalogs.
  - Blocked by: Post-`v0.1.0` frontend hardening phase.
  - Reason: i18n is explicitly deferred beyond `v0.1.0`.

Exit criteria:
- [ ] MVP SPA flows pass integration smoke checks.
- [ ] Deferred frontend items are explicitly tracked and not silently dropped.

Verification:
- [ ] Frontend integration smoke command(s) documented and passing.
- [ ] Manual responsive checks recorded for defined breakpoints.

## 15. Phase 13: Security and Observability
Implements: PRD `F6`, `F7`.

Steps:
- [ ] Step 13.1: Add CSRF protections for SPA state-changing API calls (cookie + header/token validation pattern).
- [ ] Step 13.2: Add structured logging with request IDs and external correlation IDs.
- [ ] Step 13.3: Add metrics for auth success/failure and provisioning latency.
- [ ] Step 13.4: Add security checklist and secret management validation gates.

Exit criteria:
- [ ] State-changing endpoints require CSRF validation under SPA/API request model.
- [ ] Logs/metrics support traceability across API and worker boundaries.

Verification:
- [ ] `pytest tests/security -q`
- [ ] Manual negative test: CSRF-missing request rejected for SPA API write actions.

## 16. Phase 14: Release Readiness
Implements: PRD definition-of-done completion.

Steps:
- [ ] Step 14.1: Create deployment manifests and environment docs.
- [ ] Step 14.2: Execute end-to-end staging test using sandbox credentials.
- [ ] Step 14.3: Produce incident response and manual retry runbook (including route-server SSH/BIRD rollback procedures).
- [ ] Step 14.4: Tag `v0.1.0` when PRD acceptance criteria are fully met.
- [ ] Step 14.5: Execute self-hosted-controller-only staging run (no Central credentials) including lifecycle preflight checks.
  - Blocked by: Phase 8 Step 8.1 to Step 8.5.
  - Reason: owned controller lifecycle controls must exist before self-hosted-only staging sign-off.
- [ ] Step 14.6: Execute controller disaster-recovery drill (backup -> restore -> readiness verification -> provisioning resume).
  - Blocked by: Step 14.5.
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

## 17. TODO: Phase 15 (Route Server Option B) - Persisted Route Server State Model
Status: deferred until after Phase 14 completion.

Steps:
- [ ] Step 15.1: Add persistent route-server inventory and per-request per-server sync tables/migrations.
  - Blocked by: Phase 14 completion.
  - Reason: Route Server Option B is explicitly out of active scope before release readiness.
- [ ] Step 15.2: Split route-server fanout into one queue job per route server with isolated retries and backoff.
  - Blocked by: Step 15.1.
  - Reason: per-server jobs require persisted route-server state model.
- [ ] Step 15.3: Add reconciliation worker that compares desired state to BIRD effective state and repairs drift.
  - Blocked by: Step 15.1 and Step 15.2.
  - Reason: reconciliation requires persisted desired/effective per-server state and isolated jobs.
- [ ] Step 15.4: Expose per-route-server sync state and last error in admin request detail views.
  - Blocked by: Step 15.1.
  - Reason: UI/API exposure depends on persisted state model.
- [ ] Step 15.5: Add tests for partial-failure convergence and per-server retry safety.
  - Blocked by: Step 15.1 to Step 15.4.
  - Reason: test targets do not exist until the model/jobs/reconciliation are implemented.

Exit criteria:
- [ ] Per-route-server sync status is first-class persisted state, not audit metadata only.
- [ ] Partial route-server failures are independently visible and retryable without replaying all successful servers.

Verification:
- [ ] `pytest tests/route_server_state -q`
- [ ] Manual check: one-route-server-down scenario converges after targeted retry.

## 18. TODO: Post-`v0.1.0` Frontend Hardening
Status: deferred until after Phase 14 completion.

Steps:
- [ ] Step 18.1: Add automated accessibility tooling and CI gates (keyboard flow, contrast checks, semantic status cues).
  - Blocked by: Phase 14 completion.
  - Reason: MVP release scope explicitly defers accessibility automation.
- [ ] Step 18.2: Add i18n framework and translated error/status message catalogs.
  - Blocked by: Phase 14 completion.
  - Reason: MVP release scope explicitly defers localization.
- [ ] Step 18.3: Improve data-heavy table UX at scale (virtualization/pagination persistence/mobile-specific layouts).
  - Blocked by: Phase 14 completion.
  - Reason: MVP release scope accepts baseline shadcn/Radix table behavior.
- [ ] Step 18.4: Add enhanced audit-event timeline presentation patterns for operator/admin detail views.
  - Blocked by: Phase 14 completion.
  - Reason: MVP release scope focuses on functional workflow completion.
