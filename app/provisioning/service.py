"""Provisioning workflow service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import AppSettings
from app.db.enums import RequestStatus
from app.db.models import JoinRequest
from app.db.session import SessionLocal
from app.provisioning.controller_lifecycle import (
    ControllerLifecycleError,
    ControllerPreflightResult,
    SelfHostedControllerLifecycleManager,
    create_controller_lifecycle_manager,
    run_controller_lifecycle_preflight,
)
from app.provisioning.providers import (
    ProviderNetworkNotFoundError,
    ProvisioningProvider,
    ProvisioningProviderError,
    ProvisionResult,
    create_provisioning_provider,
)
from app.provisioning.route_servers import (
    RouteServerHostFailure,
    RouteServerSyncer,
    RouteServerSyncError,
    RouteServerSyncResult,
    create_route_server_sync_service,
)
from app.repositories.audit_events import AuditEventRepository
from app.repositories.errors import InvalidStateTransitionError
from app.repositories.ipv6_allocations import Ipv6AllocationError, ZtIpv6AllocationRepository
from app.repositories.join_requests import JoinRequestRepository
from app.repositories.memberships import ZtMembershipRepository


class ProvisioningInputError(Exception):
    """Raised for deterministic local validation failures in provisioning."""

    error_code = "provisioning_input_error"


def process_join_request_provisioning(*, request_id: uuid.UUID, settings: AppSettings) -> None:
    provider = create_provisioning_provider(settings)
    route_server_sync_service = create_route_server_sync_service(settings)
    lifecycle_manager: SelfHostedControllerLifecycleManager | None = None
    if settings.zt_provider.strip().lower() == "self_hosted_controller":
        lifecycle_manager = create_controller_lifecycle_manager(settings)
    with SessionLocal() as db_session:
        process_join_request_provisioning_with_provider(
            db_session=db_session,
            request_id=request_id,
            provider=provider,
            route_server_sync_service=route_server_sync_service,
            controller_lifecycle_manager=lifecycle_manager,
        )


def process_join_request_provisioning_with_provider(
    *,
    db_session: Session,
    request_id: uuid.UUID,
    provider: ProvisioningProvider,
    route_server_sync_service: RouteServerSyncer | None = None,
    controller_lifecycle_manager: SelfHostedControllerLifecycleManager | None = None,
) -> None:
    request_repo = JoinRequestRepository(db_session)
    audit_repo = AuditEventRepository(db_session)

    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        audit_repo.create_event(
            action="provisioning.request_missing",
            target_type="join_request",
            target_id=str(request_id),
            metadata={"provider_name": provider.provider_name},
        )
        db_session.commit()
        return

    if request_row.status is not RequestStatus.APPROVED:
        audit_repo.create_event(
            action="provisioning.skipped",
            target_type="join_request",
            target_id=str(request_id),
            actor_user_id=request_row.user_id,
            metadata={
                "provider_name": provider.provider_name,
                "current_status": request_row.status.value,
                "reason": "request_not_approved",
            },
        )
        db_session.commit()
        return

    old_status: RequestStatus = request_row.status
    try:
        request_repo.transition_status(request_row, RequestStatus.PROVISIONING)
    except InvalidStateTransitionError:
        audit_repo.create_event(
            action="provisioning.skipped",
            target_type="join_request",
            target_id=str(request_id),
            actor_user_id=request_row.user_id,
            metadata={
                "provider_name": provider.provider_name,
                "current_status": request_row.status.value,
                "reason": "invalid_transition_to_provisioning",
            },
        )
        db_session.commit()
        return

    _write_status_audit_event(
        db_session=db_session,
        actor_user_id=request_row.user_id,
        request_id=request_row.id,
        old_status=old_status,
        new_status=RequestStatus.PROVISIONING,
        metadata={"provider_name": provider.provider_name},
    )
    audit_repo.create_event(
        action="provisioning.started",
        target_type="join_request",
        target_id=str(request_row.id),
        actor_user_id=request_row.user_id,
        metadata={"provider_name": provider.provider_name},
    )
    db_session.commit()

    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        return

    try:
        preflight_result: ControllerPreflightResult | None = None
        if controller_lifecycle_manager is not None:
            preflight_result = run_controller_lifecycle_preflight(
                manager=controller_lifecycle_manager,
                db_session=db_session,
                strict_fail_closed=True,
                trigger="worker_provisioning",
                actor_user_id=request_row.user_id,
                request_id=request_row.id,
            )
        allocated_assigned_ips: list[str] | None = None
        if controller_lifecycle_manager is not None:
            allocated_assigned_ips = _allocate_deterministic_ipv6(
                db_session=db_session,
                request_row=request_row,
                preflight_result=preflight_result,
            )
            db_session.commit()
        provision_result = _authorize_membership(
            provider=provider,
            request_id=request_row.id,
            asn=request_row.asn,
            zt_network_id=request_row.zt_network_id,
            node_id=request_row.node_id,
            explicit_ip_assignments=allocated_assigned_ips,
        )
        assigned_ips = (
            allocated_assigned_ips
            if allocated_assigned_ips is not None
            else provision_result.assigned_ips
        )
        if request_row.node_id is None:
            raise ProvisioningInputError("node_id is required before provisioning can run")
        membership_repo = ZtMembershipRepository(db_session)
        membership_repo.upsert_for_request(
            join_request_id=request_row.id,
            zt_network_id=request_row.zt_network_id,
            node_id=request_row.node_id,
            member_id=provision_result.member_id,
            is_authorized=provision_result.is_authorized,
            assigned_ips=assigned_ips,
        )
        route_server_results: list[RouteServerSyncResult] = []
        if route_server_sync_service is not None:
            route_server_results = route_server_sync_service.sync_desired_config(
                request_id=request_row.id,
                asn=request_row.asn,
                zt_network_id=request_row.zt_network_id,
                node_id=request_row.node_id,
                assigned_ips=assigned_ips,
            )
            if route_server_results:
                audit_repo.create_event(
                    action="route_server.sync.succeeded",
                    target_type="join_request",
                    target_id=str(request_row.id),
                    actor_user_id=request_row.user_id,
                    metadata={
                        "server_count": len(route_server_results),
                        "servers": _serialize_route_server_results(route_server_results),
                    },
                )
            else:
                audit_repo.create_event(
                    action="route_server.sync.skipped",
                    target_type="join_request",
                    target_id=str(request_row.id),
                    actor_user_id=request_row.user_id,
                    metadata={"reason": "no_route_servers_configured"},
                )
        old_status = request_row.status
        request_repo.transition_status(request_row, RequestStatus.ACTIVE)
        _write_status_audit_event(
            db_session=db_session,
            actor_user_id=request_row.user_id,
            request_id=request_row.id,
            old_status=old_status,
            new_status=RequestStatus.ACTIVE,
            metadata={
                "provider_name": provision_result.provider_name,
                "member_id": provision_result.member_id,
                "route_server_count": len(route_server_results),
            },
        )
        audit_repo.create_event(
            action="provisioning.succeeded",
            target_type="join_request",
            target_id=str(request_row.id),
            actor_user_id=request_row.user_id,
            metadata={
                "provider_name": provision_result.provider_name,
                "member_id": provision_result.member_id,
                "assigned_ips": assigned_ips,
                "route_server_count": len(route_server_results),
                "completed_at": datetime.now(UTC).isoformat(),
            },
        )
        db_session.commit()
    except (
        ControllerLifecycleError,
        ProvisioningProviderError,
        ProvisioningInputError,
        Ipv6AllocationError,
        RouteServerSyncError,
        IntegrityError,
    ) as exc:
        _mark_failed(
            db_session=db_session,
            request_id=request_id,
            provider_name=provider.provider_name,
            exc=exc,
        )


def _authorize_membership(
    *,
    provider: ProvisioningProvider,
    request_id: uuid.UUID,
    asn: int,
    zt_network_id: str,
    node_id: str | None,
    explicit_ip_assignments: list[str] | None = None,
) -> ProvisionResult:
    if node_id is None:
        raise ProvisioningInputError("node_id is required before provisioning can run")

    if not provider.validate_network(zt_network_id):
        raise ProviderNetworkNotFoundError(
            f"target network does not exist or is inactive: zt_network_id={zt_network_id}"
        )

    return provider.authorize_member(
        zt_network_id=zt_network_id,
        node_id=node_id,
        asn=asn,
        request_id=request_id,
        explicit_ip_assignments=explicit_ip_assignments,
    )


def _allocate_deterministic_ipv6(
    *,
    db_session: Session,
    request_row: JoinRequest,
    preflight_result: ControllerPreflightResult | None,
) -> list[str]:
    if preflight_result is None:
        raise ProvisioningInputError(
            "controller lifecycle preflight result is missing for deterministic IPv6 allocation"
        )

    prefixes_by_network_id = dict(preflight_result.network_derivation.expanded_suffix_ipv6_prefixes)
    network_prefix = prefixes_by_network_id.get(request_row.zt_network_id)
    if network_prefix is None:
        raise ProvisioningInputError(
            "missing deterministic IPv6 prefix for target network "
            f"zt_network_id={request_row.zt_network_id}"
        )

    assignment = ZtIpv6AllocationRepository(db_session).get_or_allocate_for_request(
        join_request_id=request_row.id,
        zt_network_id=request_row.zt_network_id,
        asn=request_row.asn,
        network_prefix=network_prefix,
    )
    return [assignment.assigned_ip]


def _mark_failed(
    *,
    db_session: Session,
    request_id: uuid.UUID,
    provider_name: str,
    exc: Exception,
) -> None:
    db_session.rollback()

    request_repo = JoinRequestRepository(db_session)
    audit_repo = AuditEventRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        audit_repo.create_event(
            action="provisioning.request_missing",
            target_type="join_request",
            target_id=str(request_id),
            metadata={
                "provider_name": provider_name,
                "error_code": _exception_error_code(exc),
                "error": str(exc),
            },
        )
        db_session.commit()
        return

    if request_row.status is not RequestStatus.PROVISIONING:
        audit_repo.create_event(
            action="provisioning.skipped",
            target_type="join_request",
            target_id=str(request_row.id),
            actor_user_id=request_row.user_id,
            metadata={
                "provider_name": provider_name,
                "current_status": request_row.status.value,
                "reason": "failed_transition_target_not_provisioning",
                "error_code": _exception_error_code(exc),
            },
        )
        db_session.commit()
        return

    old_status = request_row.status
    route_server_failure_metadata = _route_server_failure_metadata(exc)
    if route_server_failure_metadata is not None:
        audit_repo.create_event(
            action="route_server.sync.failed",
            target_type="join_request",
            target_id=str(request_row.id),
            actor_user_id=request_row.user_id,
            metadata=route_server_failure_metadata,
        )

    request_repo.transition_status(
        request_row,
        RequestStatus.FAILED,
        last_error=_exception_message(exc),
        increment_retry=True,
    )
    _write_status_audit_event(
        db_session=db_session,
        actor_user_id=request_row.user_id,
        request_id=request_row.id,
        old_status=old_status,
        new_status=RequestStatus.FAILED,
        metadata={
            "provider_name": provider_name,
            "error_code": _exception_error_code(exc),
            "error": _exception_message(exc),
        },
    )
    audit_repo.create_event(
        action="provisioning.failed",
        target_type="join_request",
        target_id=str(request_row.id),
        actor_user_id=request_row.user_id,
        metadata={
            "provider_name": provider_name,
            "error_code": _exception_error_code(exc),
            "error": _exception_message(exc),
        },
    )
    db_session.commit()


def _write_status_audit_event(
    *,
    db_session: Session,
    actor_user_id: uuid.UUID,
    request_id: uuid.UUID,
    old_status: RequestStatus,
    new_status: RequestStatus,
    metadata: dict[str, Any] | None = None,
) -> None:
    audit_metadata: dict[str, Any] = {
        "from_status": old_status.value,
        "to_status": new_status.value,
    }
    if metadata:
        audit_metadata.update(metadata)

    AuditEventRepository(db_session).create_event(
        action="request.status.changed",
        target_type="join_request",
        target_id=str(request_id),
        actor_user_id=actor_user_id,
        metadata=audit_metadata,
    )


def _exception_error_code(exc: Exception) -> str:
    if isinstance(exc, ControllerLifecycleError):
        return exc.error_code
    if isinstance(exc, ProvisioningProviderError):
        return exc.error_code
    if isinstance(exc, ProvisioningInputError):
        return exc.error_code
    if isinstance(exc, Ipv6AllocationError):
        return exc.error_code
    if isinstance(exc, RouteServerSyncError):
        return exc.error_code
    if isinstance(exc, IntegrityError):
        return "membership_integrity_error"
    return "unexpected_error"


def _exception_message(exc: Exception) -> str:
    error_code = _exception_error_code(exc)
    message = str(exc).strip()
    if not message:
        return error_code
    return f"{error_code}: {message}"


def _route_server_failure_metadata(exc: Exception) -> dict[str, Any] | None:
    if not isinstance(exc, RouteServerSyncError):
        return None

    metadata: dict[str, Any] = {
        "error_code": exc.error_code,
        "error": str(exc),
    }

    if exc.successful_results:
        metadata["successful_server_count"] = len(exc.successful_results)
        metadata["successful_servers"] = _serialize_route_server_results(exc.successful_results)
    if exc.host_failures:
        metadata["failed_server_count"] = len(exc.host_failures)
        metadata["failed_servers"] = _serialize_route_server_failures(exc.host_failures)

    return metadata


def _serialize_route_server_results(
    route_server_results: list[RouteServerSyncResult] | tuple[RouteServerSyncResult, ...],
) -> list[dict[str, str | bool]]:
    return [
        {
            "host": result.host,
            "remote_path": result.remote_path,
            "config_sha256": result.config_sha256,
            "apply_confirmed": result.apply_confirmed,
        }
        for result in route_server_results
    ]


def _serialize_route_server_failures(
    route_server_failures: list[RouteServerHostFailure] | tuple[RouteServerHostFailure, ...],
) -> list[dict[str, str | bool | None]]:
    return [
        {
            "host": failure.host,
            "remote_path": failure.remote_path,
            "stage": failure.stage,
            "command": failure.command,
            "detail": failure.detail,
            "rollback_attempted": failure.rollback_attempted,
            "rollback_succeeded": failure.rollback_succeeded,
            "rollback_error": failure.rollback_error,
        }
        for failure in route_server_failures
    ]
