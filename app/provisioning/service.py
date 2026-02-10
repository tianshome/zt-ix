"""Provisioning workflow service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import AppSettings
from app.db.enums import RequestStatus
from app.db.session import SessionLocal
from app.provisioning.providers import (
    ProviderNetworkNotFoundError,
    ProvisioningProvider,
    ProvisioningProviderError,
    ProvisionResult,
    create_provisioning_provider,
)
from app.provisioning.route_servers import (
    RouteServerSyncer,
    RouteServerSyncError,
    RouteServerSyncResult,
    create_route_server_sync_service,
)
from app.repositories.audit_events import AuditEventRepository
from app.repositories.errors import InvalidStateTransitionError
from app.repositories.join_requests import JoinRequestRepository
from app.repositories.memberships import ZtMembershipRepository


class ProvisioningInputError(Exception):
    """Raised for deterministic local validation failures in provisioning."""

    error_code = "provisioning_input_error"


def process_join_request_provisioning(*, request_id: uuid.UUID, settings: AppSettings) -> None:
    provider = create_provisioning_provider(settings)
    route_server_sync_service = create_route_server_sync_service(settings)
    with SessionLocal() as db_session:
        process_join_request_provisioning_with_provider(
            db_session=db_session,
            request_id=request_id,
            provider=provider,
            route_server_sync_service=route_server_sync_service,
        )


def process_join_request_provisioning_with_provider(
    *,
    db_session: Session,
    request_id: uuid.UUID,
    provider: ProvisioningProvider,
    route_server_sync_service: RouteServerSyncer | None = None,
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
        provision_result = _authorize_membership(
            provider=provider,
            request_id=request_row.id,
            asn=request_row.asn,
            zt_network_id=request_row.zt_network_id,
            node_id=request_row.node_id,
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
            assigned_ips=provision_result.assigned_ips,
        )
        route_server_results: list[RouteServerSyncResult] = []
        if route_server_sync_service is not None:
            route_server_results = route_server_sync_service.sync_desired_config(
                request_id=request_row.id,
                asn=request_row.asn,
                zt_network_id=request_row.zt_network_id,
                node_id=request_row.node_id,
                assigned_ips=provision_result.assigned_ips,
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
                "assigned_ips": provision_result.assigned_ips,
                "route_server_count": len(route_server_results),
                "completed_at": datetime.now(UTC).isoformat(),
            },
        )
        db_session.commit()
    except (
        ProvisioningProviderError,
        ProvisioningInputError,
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
    )


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
    if isinstance(exc, ProvisioningProviderError):
        return exc.error_code
    if isinstance(exc, ProvisioningInputError):
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


def _serialize_route_server_results(
    route_server_results: list[RouteServerSyncResult],
) -> list[dict[str, str]]:
    return [
        {
            "host": result.host,
            "remote_path": result.remote_path,
            "config_sha256": result.config_sha256,
        }
        for result in route_server_results
    ]
