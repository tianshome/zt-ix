"""Repositories for user ASN mappings."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import UserAsn


@dataclass(frozen=True, slots=True)
class UserAsnRecord:
    asn: int
    net_id: int | None = None
    net_name: str | None = None
    source: str = "peeringdb"


class UserAsnRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_by_user_id(self, user_id: uuid.UUID) -> list[UserAsn]:
        statement = select(UserAsn).where(UserAsn.user_id == user_id).order_by(UserAsn.asn.asc())
        return list(self._session.execute(statement).scalars())

    def has_asn(self, user_id: uuid.UUID, asn: int) -> bool:
        statement = select(UserAsn.id).where(UserAsn.user_id == user_id, UserAsn.asn == asn)
        return self._session.execute(statement).scalar_one_or_none() is not None

    def replace_for_user(
        self,
        user_id: uuid.UUID,
        records: Sequence[UserAsnRecord],
    ) -> list[UserAsn]:
        existing_rows = self.list_by_user_id(user_id)
        existing_by_asn = {row.asn: row for row in existing_rows}
        incoming_asns = {record.asn for record in records}

        if incoming_asns:
            self._session.execute(
                delete(UserAsn).where(UserAsn.user_id == user_id, UserAsn.asn.notin_(incoming_asns))
            )
        else:
            self._session.execute(delete(UserAsn).where(UserAsn.user_id == user_id))

        for record in records:
            existing = existing_by_asn.get(record.asn)
            if existing is None:
                self._session.add(
                    UserAsn(
                        user_id=user_id,
                        asn=record.asn,
                        net_id=record.net_id,
                        net_name=record.net_name,
                        source=record.source,
                    )
                )
            else:
                existing.net_id = record.net_id
                existing.net_name = record.net_name
                existing.source = record.source

        self._session.flush()
        return self.list_by_user_id(user_id)
