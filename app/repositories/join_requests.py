"""Repositories for join request lifecycle."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.enums import ACTIVE_REQUEST_STATUSES, RequestStatus, can_transition_status
from app.db.models import JoinRequest
from app.repositories.errors import DuplicateActiveRequestError, InvalidStateTransitionError


class JoinRequestRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, request_id: uuid.UUID) -> JoinRequest | None:
        return self._session.get(JoinRequest, request_id)

    def list_by_user_id(self, user_id: uuid.UUID) -> list[JoinRequest]:
        statement = select(JoinRequest).where(JoinRequest.user_id == user_id).order_by(
            JoinRequest.requested_at.desc()
        )
        return list(self._session.execute(statement).scalars())

    def list_for_admin(
        self,
        *,
        status: RequestStatus | None = None,
        asn: int | None = None,
        zt_network_id: str | None = None,
        min_age_minutes: int | None = None,
    ) -> list[JoinRequest]:
        statement = select(JoinRequest)

        if status is not None:
            statement = statement.where(JoinRequest.status == status)
        if asn is not None:
            statement = statement.where(JoinRequest.asn == asn)
        if zt_network_id is not None:
            statement = statement.where(JoinRequest.zt_network_id == zt_network_id)
        if min_age_minutes is not None:
            cutoff = datetime.now(UTC) - timedelta(minutes=min_age_minutes)
            statement = statement.where(JoinRequest.requested_at <= cutoff)

        statement = statement.order_by(JoinRequest.requested_at.desc())
        return list(self._session.execute(statement).scalars())

    def get_active_for_asn_network(
        self,
        asn: int,
        zt_network_id: str,
        *,
        node_id: str | None = None,
    ) -> JoinRequest | None:
        statement = select(JoinRequest).where(
            JoinRequest.asn == asn,
            JoinRequest.zt_network_id == zt_network_id,
            JoinRequest.status.in_(ACTIVE_REQUEST_STATUSES),
        )
        if node_id is None:
            statement = statement.where(JoinRequest.node_id.is_(None))
        else:
            statement = statement.where(JoinRequest.node_id == node_id)
        return self._session.execute(statement).scalar_one_or_none()

    def create_pending_request(
        self,
        *,
        user_id: uuid.UUID,
        asn: int,
        zt_network_id: str,
        node_id: str | None = None,
        notes: str | None = None,
    ) -> JoinRequest:
        request = JoinRequest(
            user_id=user_id,
            asn=asn,
            zt_network_id=zt_network_id,
            status=RequestStatus.PENDING,
            node_id=node_id,
            notes=notes,
        )
        try:
            with self._session.begin_nested():
                self._session.add(request)
                self._session.flush()
        except IntegrityError as exc:
            if _is_duplicate_active_request_error(exc):
                raise DuplicateActiveRequestError(
                    "active join request already exists for "
                    f"asn={asn} network={zt_network_id} node_id={node_id or '<none>'}"
                ) from exc
            raise
        return request

    def transition_status(
        self,
        request: JoinRequest,
        new_status: RequestStatus,
        *,
        reject_reason: str | None = None,
        last_error: str | None = None,
        increment_retry: bool = False,
    ) -> JoinRequest:
        current_status = request.status
        if not can_transition_status(current_status, new_status):
            raise InvalidStateTransitionError(current_status, new_status)

        if new_status is RequestStatus.REJECTED and not reject_reason:
            raise ValueError("reject_reason is required for rejected status")

        request.status = new_status
        now = datetime.now(UTC)

        if new_status in {RequestStatus.APPROVED, RequestStatus.REJECTED}:
            request.decided_at = now
        if new_status is RequestStatus.REJECTED:
            request.reject_reason = reject_reason
        if new_status is RequestStatus.ACTIVE:
            request.provisioned_at = now
            request.last_error = None
        if last_error is not None:
            request.last_error = last_error
        if increment_retry:
            request.retry_count += 1

        self._session.flush()
        return request


def _is_duplicate_active_request_error(exc: IntegrityError) -> bool:
    message = str(exc.orig).lower()
    return (
        "uq_join_request_active_per_asn_network_with_node" in message
        or "uq_join_request_active_per_asn_network_without_node" in message
        or "uq_join_request_active_per_asn_network" in message
        or "join_request.asn, join_request.zt_network_id, join_request.node_id" in message
        or "join_request.asn, join_request.zt_network_id" in message
    )
