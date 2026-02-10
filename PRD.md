# Product Requirements Document (PRD)
Version: 0.1
Date: 2026-02-10
Product: ZT Internet Exchange (ZT-IX) Controller

Related docs: `APP_FLOW.md`, `TECH_STACK.md`, `FRONTEND_GUIDELINES.md`, `BACKEND_STRUCTURE.md`, `IMPLEMENTATION_PLAN.md`

## 1. Objective
Build a self-service controller that lets verified network operators join a virtual IX fabric on ZeroTier, using PeeringDB identity as the source of truth for operator/account context and a configurable ZeroTier provisioning provider.

## 2. Target Users
1. Network operators who maintain ASN records in PeeringDB.
2. IX administrators who control acceptance and policy.
3. NOC/operations staff who need clear provisioning status and auditability.

## 3. Problem Statement
Virtual IX onboarding is often manual and inconsistent. Operators need a standardized flow to prove identity, request access, and get provisioned into a ZeroTier-based peering fabric with minimal human overhead and strong controls.

## 4. In Scope
1. PeeringDB OIDC login.
2. ASN/network context retrieval from PeeringDB APIs.
3. Join request workflow (submit, review, approve/reject).
4. ZeroTier member provisioning via a provider abstraction.
5. Phase 1 providers: ZeroTier Central API token auth and self-hosted ZeroTier controller API auth.
6. Status tracking and audit logging.
7. Basic admin interface for policy and approvals.

## 5. Out of Scope (Non-Goals)
1. BGP session orchestration across routers.
2. Billing/invoicing.
3. Full NMS replacement.
4. Multi-cloud overlay orchestration outside ZeroTier.
5. Custom identity provider support beyond PeeringDB (phase 1).
6. Automated deployment/management of custom ZeroTier roots/planet infrastructure.

## 6. User Stories
1. As an operator, I can log in with PeeringDB so I do not create a separate identity.
2. As an operator, I can select my eligible ASN and request IX access.
3. As an admin, I can approve or reject requests with clear reasons.
4. As an admin, I can trigger (or auto-trigger) ZeroTier authorization for approved requests through the configured provider.
5. As an operator, I can see whether my request is pending, active, or failed.
6. As an auditor, I can view immutable logs of key actions.

## 7. Features and Acceptance Criteria

### F1. PeeringDB Authentication
Acceptance criteria:
1. User can initiate login via PeeringDB OIDC.
2. OAuth2/OIDC callback validates state and nonce before session creation.
3. On success, a local user record is upserted by `peeringdb_user_id`.
4. On callback errors, user sees recoverable error page and can retry.

### F2. ASN Discovery and Eligibility
Acceptance criteria:
1. System queries PeeringDB APIs with bearer token and fetches user-eligible network context.
2. User can only submit request against ASN records they are authorized to represent.
3. If no eligible ASN is found, UI shows explicit reason and support path.

### F3. Join Request Workflow
Acceptance criteria:
1. Operator can create one active request per ASN per target IX network.
2. Duplicate in-flight requests are blocked with a deterministic message.
3. Request status transitions are enforced: `pending -> approved/rejected -> provisioning -> active/failed`.
4. Rejection requires reason text stored in audit log.

### F4. ZeroTier Provisioning
Acceptance criteria:
1. Approved request triggers a provider-agnostic ZeroTier member authorization task.
2. Provider is selected by configuration (`central` or `self_hosted_controller`) without changing workflow states.
3. Provisioning is idempotent for retries (same request does not create duplicate active membership rows).
4. Failures persist reason, last error time, and retry count.
5. Successful provisioning stores ZeroTier network/member identifiers.

### F5. Admin Controls
Acceptance criteria:
1. Admins can list and filter requests by status and ASN.
2. Admins can approve/reject requests with audit entry.
3. Admins can re-run provisioning for failed requests.

### F6. Auditing and Observability
Acceptance criteria:
1. Every auth event, request status change, and provisioning action creates an audit event.
2. Each audit event includes actor, action, target, timestamp, and metadata.
3. Operational logs include external API correlation IDs when available.

## 8. Success Criteria
1. 90%+ of valid operator requests complete without manual backend intervention.
2. Median onboarding time from login to active membership < 10 minutes (non-manual path).
3. Zero critical-severity security findings in auth/session handling.
4. 100% of approval/rejection/provisioning transitions appear in audit log.

## 9. Constraints and Risks
1. PeeringDB scope/permissions model may evolve; integration must isolate provider-specific logic.
2. ZeroTier provider credential management (Central API token or self-hosted controller auth token) is high-impact and must use strict secret storage.
3. Incorrect ASN authorization logic can cause unauthorized onboarding.
4. Provider API differences can cause behavior drift if provisioning logic is not contract-tested.

## 10. Definition of Done
1. All in-scope features meet acceptance criteria.
2. Critical auth/provisioning paths have automated tests.
3. Deployment docs and runbook exist.
4. Security checklist completed for session, CSRF, and secret management.
5. Provisioning adapter contract tests cover both `central` and `self_hosted_controller` modes.
