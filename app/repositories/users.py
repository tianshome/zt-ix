"""Repositories for app user persistence."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import normalize_login_username
from app.db.models import AppUser


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, user_id: uuid.UUID) -> AppUser | None:
        return self._session.get(AppUser, user_id)

    def get_by_peeringdb_user_id(self, peeringdb_user_id: int) -> AppUser | None:
        statement = select(AppUser).where(AppUser.peeringdb_user_id == peeringdb_user_id)
        return self._session.execute(statement).scalar_one_or_none()

    def get_by_username(self, username: str) -> AppUser | None:
        statement = select(AppUser).where(AppUser.username == normalize_login_username(username))
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

    def upsert_local_user(
        self,
        *,
        username: str,
        full_name: str | None = None,
        email: str | None = None,
        is_admin: bool | None = None,
    ) -> AppUser:
        normalized_username = normalize_login_username(username)
        existing = self.get_by_username(normalized_username)
        if existing is None:
            existing = AppUser(
                peeringdb_user_id=None,
                username=normalized_username,
                full_name=full_name,
                email=email,
                is_admin=bool(is_admin),
            )
            self._session.add(existing)
        else:
            existing.username = normalized_username
            if full_name is not None:
                existing.full_name = full_name
            if email is not None:
                existing.email = email
            if is_admin is not None:
                existing.is_admin = is_admin

        self._session.flush()
        return existing
