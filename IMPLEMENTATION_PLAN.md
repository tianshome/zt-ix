# Implementation Plan
Version: 0.1
Date: 2026-02-10

Related docs: `PRD.md`, `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`

## Phase 1: Project Bootstrap
1. Step 1.1: Initialize Python project layout (`app/`, `tests/`, `alembic/`).
2. Step 1.2: Add dependencies pinned in `TECH_STACK.md`.
3. Step 1.3: Configure linting/type/test tooling (`ruff`, `mypy`, `pytest`).
4. Step 1.4: Add `.env.example` with required secrets, endpoint settings, and `ZT_PROVIDER` mode config.

## Phase 2: Data and Migration Foundation
1. Step 2.1: Configure SQLAlchemy models for schema in `BACKEND_STRUCTURE.md`.
2. Step 2.2: Initialize Alembic and create initial migration.
3. Step 2.3: Build repository layer for users, ASNs, requests, and audits.
4. Step 2.4: Add DB unit tests for constraints and status transitions.

## Phase 3: Auth Integration (PeeringDB)
1. Step 3.1: Implement `/auth/login` with state/nonce/PKCE generation.
2. Step 3.2: Implement `/auth/callback` token exchange + validation.
3. Step 3.3: Upsert user and fetch ASN/network context from PeeringDB API.
4. Step 3.4: Establish secure session middleware and logout behavior.
5. Step 3.5: Add integration tests for success and failure callback paths.

## Phase 4: Request Workflow
1. Step 4.1: Implement request creation endpoint and duplicate protections.
2. Step 4.2: Build operator dashboard and request detail pages.
3. Step 4.3: Build admin queue and approve/reject APIs.
4. Step 4.4: Add audit events for all state transitions.
5. Step 4.5: Add API and UI tests for workflow transitions.

## Phase 5: ZeroTier Provisioning
1. Step 5.1: Create provider-agnostic ZeroTier provisioning interface and normalized response model.
2. Step 5.2: Implement `central` provider adapter using ZeroTier Central API token auth.
3. Step 5.3: Implement `self_hosted_controller` provider adapter using local controller API and `X-ZT1-Auth`.
4. Step 5.4: Update Celery provisioning task to resolve provider from `ZT_PROVIDER`.
5. Step 5.5: Add idempotency keying and safe retry behavior shared across providers.
6. Step 5.6: Persist membership details and expose them in request API.
7. Step 5.7: Add failure handling and admin retry action for provider/network/auth errors.
8. Step 5.8: Add unit/integration tests for provider contract, adapter selection, and retry semantics.

## Phase 6: Frontend Hardening
1. Step 6.1: Apply styles and components from `FRONTEND_GUIDELINES.md`.
2. Step 6.2: Implement responsive layout for mobile and desktop.
3. Step 6.3: Add accessibility checks (keyboard, focus, contrast).
4. Step 6.4: Add empty/error states for all critical screens.

## Phase 7: Security and Observability
1. Step 7.1: Add CSRF protections for all state-changing form actions.
2. Step 7.2: Add structured logging with request IDs and external correlation IDs.
3. Step 7.3: Add metrics for auth success/failure and provisioning latency.
4. Step 7.4: Add security review checklist and secret management validation.

## Phase 8: Release Readiness
1. Step 8.1: Create deployment manifests and environment docs.
2. Step 8.2: Execute end-to-end staging test using sandbox credentials.
3. Step 8.3: Produce runbook for incident response and manual retries.
4. Step 8.4: Tag v0.1.0 once acceptance criteria from `PRD.md` are met.
