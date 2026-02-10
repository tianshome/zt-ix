"""Repositories for app user persistence."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AppUser


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, user_id: uuid.UUID) -> AppUser | None:
        return self._session.get(AppUser, user_id)

    def get_by_peeringdb_user_id(self, peeringdb_user_id: int) -> AppUser | None:
        statement = select(AppUser).where(AppUser.peeringdb_user_id == peeringdb_user_id)
        return self._session.execute(statement).scalar_one_or_none()

    def upsert_peeringdb_user(
        self,
        *,
        peeringdb_user_id: int,
        username: str,
        full_name: str | None,
        email: str | None,
        is_admin: bool | None = None,
    ) -> AppUser:
        existing = self.get_by_peeringdb_user_id(peeringdb_user_id)
        if existing is None:
            existing = AppUser(
                peeringdb_user_id=peeringdb_user_id,
                username=username,
                full_name=full_name,
                email=email,
                is_admin=bool(is_admin),
            )
            self._session.add(existing)
        else:
            existing.username = username
            existing.full_name = full_name
            existing.email = email
            if is_admin is not None:
                existing.is_admin = is_admin

        self._session.flush()
        return existing
