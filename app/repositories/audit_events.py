"""Repositories for audit events."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent


class AuditEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_event(
        self,
        *,
        action: str,
        target_type: str,
        target_id: str,
        actor_user_id: uuid.UUID | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            event_metadata=dict(metadata or {}),
        )
        self._session.add(event)
        self._session.flush()
        return event

    def list_for_target(self, *, target_type: str, target_id: str) -> list[AuditEvent]:
        statement = (
            select(AuditEvent)
            .where(AuditEvent.target_type == target_type, AuditEvent.target_id == target_id)
            .order_by(AuditEvent.created_at.asc())
        )
        return list(self._session.execute(statement).scalars())
