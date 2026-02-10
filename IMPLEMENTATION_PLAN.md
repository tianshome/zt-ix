# Implementation Plan
Version: 0.2
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## 1. Planning Assumptions and Open Questions
1. Assumption: phase 1 uses admin approval as default decision control.
2. Assumption: provider mode is selected by `ZT_PROVIDER` and cannot be switched per-request.
3. Open question: policy-based auto-approval scope (if any) remains deferred pending product decision.
4. Open question: target retry limits/backoff constants should be finalized before phase 5 implementation.

## 2. Traceability Map
1. PRD `F1` and `F2` map to phases 3 and 4.
2. PRD `F3` and `F5` map to phase 4.
3. PRD `F4` maps to phase 5.
4. PRD `F6` and `F7` map to phases 4, 5, and 7.
5. Frontend UX/accessibility requirements map to phase 6.
6. Release and operational requirements map to phase 8.

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

## 5. Phase 3: Auth Integration (PeeringDB)
Implements: PRD `F1`, part of `F2`, `F7`.

Steps:
1. Step 3.1: Implement `/auth/login` with state/nonce/PKCE generation.
2. Step 3.2: Implement `/auth/callback` token exchange + state/nonce validation.
3. Step 3.3: Upsert user and fetch authorized ASN/network context from PeeringDB.
4. Step 3.4: Establish secure session middleware and logout behavior.
5. Step 3.5: Add integration tests for success and failure callback paths.

Exit criteria:
1. Valid login creates session and user profile.
2. Invalid callback paths fail safely and audit appropriately.

Verification:
1. `pytest tests/auth -q`
2. Manual check: `/auth/login -> /auth/callback -> /onboarding`.

## 6. Phase 4: Request Workflow
Implements: PRD `F2`, `F3`, `F5`, `F6`.

Steps:
1. Step 4.1: Implement request creation endpoint with ASN ownership and duplicate protections.
2. Step 4.2: Build operator dashboard and request detail pages.
3. Step 4.3: Build admin queue and approve/reject APIs with role checks.
4. Step 4.4: Emit audit events for all workflow state transitions.
5. Step 4.5: Add API and UI tests for transitions and conflict handling.

Exit criteria:
1. Operator can submit request and track state.
2. Admin can approve/reject with proper validation and auditing.

Verification:
1. `pytest tests/workflow -q`
2. Manual checks:
   - duplicate request conflict path
   - reject-without-reason validation path

## 7. Phase 5: ZeroTier Provisioning
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

Exit criteria:
1. Both provider modes pass shared contract tests.
2. Re-running same provisioning request does not duplicate membership rows.

Verification:
1. `pytest tests/provisioning -q`
2. Manual checks:
   - provider selection by `ZT_PROVIDER`
   - admin retry from `failed` state

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
3. Step 8.3: Produce incident response and manual retry runbook.
4. Step 8.4: Tag `v0.1.0` when PRD acceptance criteria are fully met.

Exit criteria:
1. Staging walkthrough covers operator, admin, and retry paths.
2. Runbook and deployment docs are reviewed and current.

Verification:
1. E2E staging checklist signed off.
2. Final regression test pass before release tag.
