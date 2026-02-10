"""Request workflow APIs and page routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.config import AppSettings
from app.db.enums import RequestStatus
from app.db.models import AppUser, AuditEvent, JoinRequest, UserAsn, ZtMembership
from app.dependencies import (
    SessionActor,
    get_admin_session_actor,
    get_app_settings,
    get_db_session,
    get_session_actor,
)
from app.provisioning.tasks import enqueue_provision_join_request
from app.repositories.audit_events import AuditEventRepository
from app.repositories.errors import DuplicateActiveRequestError, InvalidStateTransitionError
from app.repositories.join_requests import JoinRequestRepository
from app.repositories.user_asns import UserAsnRepository
from app.repositories.user_network_access import UserNetworkAccessRepository
from app.repositories.users import UserRepository
from app.repositories.zt_networks import ZtNetworkRepository

router = APIRouter(tags=["workflow"])
DbSessionDep = Annotated[Session, Depends(get_db_session)]
SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]


class CreateJoinRequestPayload(BaseModel):
    asn: int = Field(gt=0)
    zt_network_id: str = Field(min_length=16, max_length=16)
    node_id: str | None = None
    notes: str | None = None

    @field_validator("zt_network_id")
    @classmethod
    def _normalize_network_id(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("node_id")
    @classmethod
    def _normalize_node_id(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip().lower()
        if not normalized:
            return None
        if len(normalized) != 10:
            raise ValueError("node_id must be 10 characters")
        return normalized

    @field_validator("notes")
    @classmethod
    def _normalize_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class RejectJoinRequestPayload(BaseModel):
    reject_reason: str | None = None

    @field_validator("reject_reason")
    @classmethod
    def _normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


@router.get("/dashboard", name="dashboard_page")
def dashboard_page(
    request: Request,
    db_session: DbSessionDep,
) -> dict[str, Any]:
    actor = _require_page_actor(request)
    request_repo = JoinRequestRepository(db_session)
    user_requests = request_repo.list_by_user_id(actor.user_id)
    return {
        "status": "ok",
        "request_count": len(user_requests),
        "requests": [_serialize_join_request(item) for item in user_requests],
    }


@router.get("/requests/{request_id}", name="request_detail_page")
def request_detail_page(
    request: Request,
    request_id: uuid.UUID,
    db_session: DbSessionDep,
) -> dict[str, Any]:
    actor = _require_page_actor(request)
    request_repo = JoinRequestRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None or request_row.user_id != actor.user_id:
        raise HTTPException(status_code=404, detail="request not found")

    audit_events = AuditEventRepository(db_session).list_for_target(
        target_type="join_request",
        target_id=str(request_row.id),
    )
    return {
        "status": "ok",
        "request": _serialize_join_request(request_row),
        "audit_events": [_serialize_audit_event(event) for event in audit_events],
    }


@router.get("/admin/requests", name="admin_requests_page")
def admin_requests_page(
    request: Request,
    db_session: DbSessionDep,
    status: RequestStatus | None = None,
    asn: int | None = None,
    zt_network_id: str | None = None,
    min_age_minutes: int | None = Query(default=None, ge=0),
) -> dict[str, Any]:
    _require_page_actor(request, require_admin=True)
    request_repo = JoinRequestRepository(db_session)
    admin_requests = request_repo.list_for_admin(
        status=status,
        asn=asn,
        zt_network_id=zt_network_id,
        min_age_minutes=min_age_minutes,
    )
    return {
        "status": "ok",
        "request_count": len(admin_requests),
        "filters": {
            "status": status.value if status else None,
            "asn": asn,
            "zt_network_id": zt_network_id,
            "min_age_minutes": min_age_minutes,
        },
        "requests": [_serialize_join_request(item) for item in admin_requests],
    }


@router.get("/admin/requests/{request_id}", name="admin_request_detail_page")
def admin_request_detail_page(
    request: Request,
    request_id: uuid.UUID,
    db_session: DbSessionDep,
) -> dict[str, Any]:
    _require_page_actor(request, require_admin=True)
    request_repo = JoinRequestRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        raise HTTPException(status_code=404, detail="request not found")

    audit_events = AuditEventRepository(db_session).list_for_target(
        target_type="join_request",
        target_id=str(request_row.id),
    )
    return {
        "status": "ok",
        "request": _serialize_join_request(request_row),
        "audit_events": [_serialize_audit_event(event) for event in audit_events],
    }


@router.get("/api/v1/me")
def api_me(
    request: Request,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    user_repo = UserRepository(db_session)
    user_row = user_repo.get_by_id(actor.user_id)
    if user_row is None:
        return _error_response(
            status_code=401,
            code="unauthenticated",
            message="Authentication required.",
        )

    asn_rows = UserAsnRepository(db_session).list_by_user_id(actor.user_id)
    return _success_response(
        {
            "user": _serialize_user(user_row),
            "asns": [_serialize_user_asn(row) for row in asn_rows],
        }
    )


@router.get("/api/v1/asns")
def api_asns(
    request: Request,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    asn_rows = UserAsnRepository(db_session).list_by_user_id(actor.user_id)
    return _success_response({"asns": [_serialize_user_asn(row) for row in asn_rows]})


@router.post("/api/v1/requests")
def api_create_request(
    request: Request,
    payload: CreateJoinRequestPayload,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    user_asn_repo = UserAsnRepository(db_session)
    if not user_asn_repo.has_asn(actor.user_id, payload.asn):
        return _error_response(
            status_code=403,
            code="asn_not_authorized",
            message="You are not authorized to create requests for this ASN.",
            details={"asn": payload.asn},
        )

    network_repo = ZtNetworkRepository(db_session)
    network_row = network_repo.get_active_by_id(payload.zt_network_id)
    if network_row is None:
        return _error_response(
            status_code=400,
            code="invalid_network",
            message="Target ZeroTier network was not found or is inactive.",
            details={"zt_network_id": payload.zt_network_id},
        )

    allowed_network_ids = UserNetworkAccessRepository(db_session).list_network_ids_by_user_id(
        actor.user_id
    )
    if allowed_network_ids and network_row.id not in allowed_network_ids:
        return _error_response(
            status_code=403,
            code="network_not_authorized",
            message="You are not authorized to create requests for this network.",
            details={
                "zt_network_id": network_row.id,
                "allowed_network_ids": sorted(allowed_network_ids),
            },
        )

    request_repo = JoinRequestRepository(db_session)
    audit_repo = AuditEventRepository(db_session)
    try:
        created = request_repo.create_pending_request(
            user_id=actor.user_id,
            asn=payload.asn,
            zt_network_id=network_row.id,
            node_id=payload.node_id,
            notes=payload.notes,
        )
    except DuplicateActiveRequestError:
        existing = request_repo.get_active_for_asn_network(payload.asn, network_row.id)
        detail: dict[str, Any] = {"asn": payload.asn, "zt_network_id": network_row.id}
        if existing is not None and existing.user_id == actor.user_id:
            detail["existing_request_id"] = str(existing.id)
            detail["existing_request_url"] = f"/requests/{existing.id}"
        return _error_response(
            status_code=409,
            code="duplicate_active_request",
            message="An active request already exists for this ASN and network.",
            details=detail,
        )

    audit_repo.create_event(
        action="request.created",
        target_type="join_request",
        target_id=str(created.id),
        actor_user_id=actor.user_id,
        metadata={
            "from_status": "none",
            "to_status": created.status.value,
            "asn": payload.asn,
            "zt_network_id": network_row.id,
        },
    )
    db_session.commit()

    return _success_response({"request": _serialize_join_request(created)}, status_code=201)


@router.get("/api/v1/requests")
def api_list_requests(
    request: Request,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    request_rows = JoinRequestRepository(db_session).list_by_user_id(actor.user_id)
    return _success_response({"requests": [_serialize_join_request(row) for row in request_rows]})


@router.get("/api/v1/requests/{request_id}")
def api_request_detail(
    request: Request,
    request_id: uuid.UUID,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    request_row = JoinRequestRepository(db_session).get_by_id(request_id)
    if request_row is None or request_row.user_id != actor.user_id:
        return _error_response(
            status_code=404,
            code="request_not_found",
            message="Request not found.",
        )

    return _success_response({"request": _serialize_join_request(request_row)})


@router.post("/api/v1/admin/requests/{request_id}/approve")
def api_admin_approve(
    request: Request,
    request_id: uuid.UUID,
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request, require_admin=True)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    request_repo = JoinRequestRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        return _error_response(
            status_code=404,
            code="request_not_found",
            message="Request not found.",
        )

    old_status = request_row.status
    try:
        request_repo.transition_status(request_row, RequestStatus.APPROVED)
    except InvalidStateTransitionError:
        return _invalid_transition_response(request_row)

    _enqueue_provisioning_attempt(request_id=request_row.id, settings=settings)
    _write_status_audit_event(
        db_session=db_session,
        actor_user_id=actor.user_id,
        request_row=request_row,
        old_status=old_status,
        metadata={"queue_action": "provisioning_enqueued"},
    )
    db_session.commit()
    return _success_response({"request": _serialize_join_request(request_row)})


@router.post("/api/v1/admin/requests/{request_id}/reject")
def api_admin_reject(
    request: Request,
    request_id: uuid.UUID,
    payload: RejectJoinRequestPayload,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request, require_admin=True)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    reject_reason = payload.reject_reason
    if reject_reason is None:
        return _error_response(
            status_code=400,
            code="reject_reason_required",
            message="Reject reason is required.",
        )

    request_repo = JoinRequestRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        return _error_response(
            status_code=404,
            code="request_not_found",
            message="Request not found.",
        )

    old_status = request_row.status
    try:
        request_repo.transition_status(
            request_row,
            RequestStatus.REJECTED,
            reject_reason=reject_reason,
        )
    except InvalidStateTransitionError:
        return _invalid_transition_response(request_row)

    _write_status_audit_event(
        db_session=db_session,
        actor_user_id=actor.user_id,
        request_row=request_row,
        old_status=old_status,
        metadata={"reject_reason": reject_reason},
    )
    db_session.commit()
    return _success_response({"request": _serialize_join_request(request_row)})


@router.post("/api/v1/admin/requests/{request_id}/retry")
def api_admin_retry(
    request: Request,
    request_id: uuid.UUID,
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> JSONResponse:
    actor, auth_error = _require_api_actor(request, require_admin=True)
    if auth_error is not None:
        return auth_error
    assert actor is not None

    request_repo = JoinRequestRepository(db_session)
    request_row = request_repo.get_by_id(request_id)
    if request_row is None:
        return _error_response(
            status_code=404,
            code="request_not_found",
            message="Request not found.",
        )
    if request_row.status is not RequestStatus.FAILED:
        return _error_response(
            status_code=409,
            code="invalid_status_transition",
            message="Retry is only allowed for failed requests.",
            details={
                "current_status": request_row.status.value,
                "required_status": RequestStatus.FAILED.value,
            },
        )

    old_status = request_row.status
    try:
        request_repo.transition_status(request_row, RequestStatus.APPROVED)
    except InvalidStateTransitionError:
        return _invalid_transition_response(request_row)

    _enqueue_provisioning_attempt(request_id=request_row.id, settings=settings)
    _write_status_audit_event(
        db_session=db_session,
        actor_user_id=actor.user_id,
        request_row=request_row,
        old_status=old_status,
        metadata={"queue_action": "retry_enqueued"},
    )
    db_session.commit()
    return _success_response({"request": _serialize_join_request(request_row)})


def _require_api_actor(
    request: Request,
    *,
    require_admin: bool = False,
) -> tuple[SessionActor | None, JSONResponse | None]:
    try:
        actor = get_session_actor(request)
        if require_admin:
            actor = get_admin_session_actor(actor)
    except HTTPException as exc:
        if exc.status_code == 401:
            return None, _error_response(
                status_code=401,
                code="unauthenticated",
                message="Authentication required.",
            )
        if exc.status_code == 403:
            return None, _error_response(
                status_code=403,
                code="forbidden",
                message="Admin role required.",
            )
        return None, _error_response(
            status_code=exc.status_code,
            code="request_rejected",
            message=str(exc.detail),
        )
    return actor, None


def _require_page_actor(request: Request, *, require_admin: bool = False) -> SessionActor:
    actor = get_session_actor(request)
    if require_admin:
        return get_admin_session_actor(actor)
    return actor


def _success_response(data: dict[str, Any], *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"data": data})


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            }
        },
    )


def _invalid_transition_response(request_row: JoinRequest) -> JSONResponse:
    return _error_response(
        status_code=409,
        code="invalid_status_transition",
        message="Request status transition is not allowed from current state.",
        details={"current_status": request_row.status.value},
    )


def _write_status_audit_event(
    *,
    db_session: Session,
    actor_user_id: uuid.UUID,
    request_row: JoinRequest,
    old_status: RequestStatus,
    metadata: dict[str, Any] | None = None,
) -> None:
    audit_metadata = {
        "from_status": old_status.value,
        "to_status": request_row.status.value,
    }
    if metadata:
        audit_metadata.update(metadata)

    AuditEventRepository(db_session).create_event(
        action="request.status.changed",
        target_type="join_request",
        target_id=str(request_row.id),
        actor_user_id=actor_user_id,
        metadata=audit_metadata,
    )


def _enqueue_provisioning_attempt(*, request_id: uuid.UUID, settings: AppSettings) -> None:
    enqueue_provision_join_request(request_id=request_id, settings=settings)


def _serialize_user(user: AppUser) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "peeringdb_user_id": user.peeringdb_user_id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": _iso_datetime(user.created_at),
        "updated_at": _iso_datetime(user.updated_at),
    }


def _serialize_user_asn(row: UserAsn) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "asn": row.asn,
        "net_id": row.net_id,
        "net_name": row.net_name,
        "source": row.source,
        "verified_at": _iso_datetime(row.verified_at),
        "created_at": _iso_datetime(row.created_at),
    }


def _serialize_membership(row: ZtMembership | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": str(row.id),
        "join_request_id": str(row.join_request_id),
        "zt_network_id": row.zt_network_id,
        "node_id": row.node_id,
        "member_id": row.member_id,
        "is_authorized": row.is_authorized,
        "assigned_ips": row.assigned_ips,
        "created_at": _iso_datetime(row.created_at),
        "updated_at": _iso_datetime(row.updated_at),
    }


def _serialize_join_request(request_row: JoinRequest) -> dict[str, Any]:
    return {
        "id": str(request_row.id),
        "user_id": str(request_row.user_id),
        "asn": request_row.asn,
        "zt_network_id": request_row.zt_network_id,
        "status": request_row.status.value,
        "node_id": request_row.node_id,
        "notes": request_row.notes,
        "reject_reason": request_row.reject_reason,
        "last_error": request_row.last_error,
        "retry_count": request_row.retry_count,
        "requested_at": _iso_datetime(request_row.requested_at),
        "decided_at": _iso_datetime(request_row.decided_at),
        "provisioned_at": _iso_datetime(request_row.provisioned_at),
        "updated_at": _iso_datetime(request_row.updated_at),
        "membership": _serialize_membership(request_row.membership),
    }


def _serialize_audit_event(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "metadata": event.event_metadata,
        "created_at": _iso_datetime(event.created_at),
    }


def _iso_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC).isoformat()
    return value.astimezone(UTC).isoformat()
