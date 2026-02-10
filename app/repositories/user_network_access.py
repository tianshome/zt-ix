"""Repository for user-to-ZeroTier-network access assignments."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import UserNetworkAccess


class UserNetworkAccessRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_by_user_id(self, user_id: uuid.UUID) -> list[UserNetworkAccess]:
        statement = (
            select(UserNetworkAccess)
            .where(UserNetworkAccess.user_id == user_id)
            .order_by(UserNetworkAccess.zt_network_id.asc())
        )
        return list(self._session.execute(statement).scalars())

    def list_network_ids_by_user_id(self, user_id: uuid.UUID) -> set[str]:
        statement = select(UserNetworkAccess.zt_network_id).where(
            UserNetworkAccess.user_id == user_id
        )
        return {value for value in self._session.execute(statement).scalars()}

    def replace_for_user(
        self,
        user_id: uuid.UUID,
        zt_network_ids: Sequence[str],
        *,
        source: str = "local",
    ) -> list[UserNetworkAccess]:
        normalized_ids = _normalize_network_ids(zt_network_ids)
        existing_rows = self.list_by_user_id(user_id)
        existing_by_network_id = {row.zt_network_id: row for row in existing_rows}
        incoming_ids = set(normalized_ids)

        if incoming_ids:
            self._session.execute(
                delete(UserNetworkAccess).where(
                    UserNetworkAccess.user_id == user_id,
                    UserNetworkAccess.zt_network_id.notin_(incoming_ids),
                )
            )
        else:
            self._session.execute(
                delete(UserNetworkAccess).where(UserNetworkAccess.user_id == user_id)
            )

        for network_id in normalized_ids:
            existing = existing_by_network_id.get(network_id)
            if existing is None:
                self._session.add(
                    UserNetworkAccess(
                        user_id=user_id,
                        zt_network_id=network_id,
                        source=source,
                    )
                )
            else:
                existing.source = source

        self._session.flush()
        return self.list_by_user_id(user_id)


def _normalize_network_ids(zt_network_ids: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in zt_network_ids:
        value = raw_value.strip().lower()
        if len(value) != 16:
            raise ValueError(f"invalid zt_network_id: {raw_value}")
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized
