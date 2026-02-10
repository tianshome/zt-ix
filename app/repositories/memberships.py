"""Repositories for ZeroTier membership rows."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ZtMembership


class ZtMembershipRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_request_id(self, join_request_id: uuid.UUID) -> ZtMembership | None:
        statement = select(ZtMembership).where(ZtMembership.join_request_id == join_request_id)
        return self._session.execute(statement).scalar_one_or_none()

    def upsert_for_request(
        self,
        *,
        join_request_id: uuid.UUID,
        zt_network_id: str,
        node_id: str,
        member_id: str,
        is_authorized: bool,
        assigned_ips: list[str],
    ) -> ZtMembership:
        existing = self.get_by_request_id(join_request_id)
        if existing is None:
            existing = ZtMembership(
                join_request_id=join_request_id,
                zt_network_id=zt_network_id,
                node_id=node_id,
                member_id=member_id,
                is_authorized=is_authorized,
                assigned_ips=assigned_ips,
            )
            self._session.add(existing)
        else:
            existing.zt_network_id = zt_network_id
            existing.node_id = node_id
            existing.member_id = member_id
            existing.is_authorized = is_authorized
            existing.assigned_ips = assigned_ips

        self._session.flush()
        return existing
