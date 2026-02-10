"""Repository for local credential persistence and lookup."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.auth import normalize_login_username
from app.db.models import LocalCredential


class LocalCredentialRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_user_id(self, user_id: uuid.UUID) -> LocalCredential | None:
        statement = (
            select(LocalCredential)
            .options(joinedload(LocalCredential.user))
            .where(LocalCredential.user_id == user_id)
        )
        return self._session.execute(statement).scalar_one_or_none()

    def get_by_login_username(self, login_username: str) -> LocalCredential | None:
        normalized = normalize_login_username(login_username)
        statement = (
            select(LocalCredential)
            .options(joinedload(LocalCredential.user))
            .where(LocalCredential.login_username == normalized)
        )
        return self._session.execute(statement).scalar_one_or_none()

    def upsert_for_user(
        self,
        *,
        user_id: uuid.UUID,
        login_username: str,
        password_hash: str,
        is_enabled: bool | None = None,
    ) -> LocalCredential:
        normalized = normalize_login_username(login_username)
        row = self.get_by_user_id(user_id)
        if row is None:
            row = LocalCredential(
                user_id=user_id,
                login_username=normalized,
                password_hash=password_hash,
                is_enabled=True if is_enabled is None else is_enabled,
            )
            self._session.add(row)
        else:
            row.login_username = normalized
            row.password_hash = password_hash
            if is_enabled is not None:
                row.is_enabled = is_enabled

        self._session.flush()
        return row

    def touch_last_login(self, row: LocalCredential, *, at: datetime | None = None) -> None:
        row.last_login_at = at or datetime.now(UTC)
        self._session.flush()
