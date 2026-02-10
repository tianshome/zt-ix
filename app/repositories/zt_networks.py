"""Repositories for ZeroTier network rows."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ZtNetwork


class ZtNetworkRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, zt_network_id: str) -> ZtNetwork | None:
        return self._session.get(ZtNetwork, zt_network_id)

    def get_active_by_id(self, zt_network_id: str) -> ZtNetwork | None:
        statement = select(ZtNetwork).where(
            ZtNetwork.id == zt_network_id,
            ZtNetwork.is_active.is_(True),
        )
        return self._session.execute(statement).scalar_one_or_none()

    def list_active(self) -> list[ZtNetwork]:
        statement = (
            select(ZtNetwork)
            .where(ZtNetwork.is_active.is_(True))
            .order_by(ZtNetwork.id.asc())
        )
        return list(self._session.execute(statement).scalars())
