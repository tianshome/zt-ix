"""Repository for OAuth state/nonce rows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import OauthStateNonce


class OauthStateConsumeStatus(StrEnum):
    CONSUMED = "consumed"
    MISSING = "missing"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class OauthStateConsumeResult:
    status: OauthStateConsumeStatus
    row: OauthStateNonce | None = None


class OauthStateNonceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        state: str,
        nonce: str,
        pkce_verifier: str,
        redirect_uri: str,
        expires_at: datetime,
    ) -> OauthStateNonce:
        row = OauthStateNonce(
            state=state,
            nonce=nonce,
            pkce_verifier=pkce_verifier,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def consume_state(
        self,
        *,
        state: str,
        now: datetime | None = None,
    ) -> OauthStateConsumeResult:
        consumed_at = _as_utc(now or datetime.now(UTC))
        statement = select(OauthStateNonce).where(OauthStateNonce.state == state)
        row = self._session.execute(statement).scalar_one_or_none()
        if row is None:
            return OauthStateConsumeResult(status=OauthStateConsumeStatus.MISSING)

        self._session.delete(row)
        self._session.flush()

        if _as_utc(row.expires_at) <= consumed_at:
            return OauthStateConsumeResult(status=OauthStateConsumeStatus.EXPIRED)

        return OauthStateConsumeResult(status=OauthStateConsumeStatus.CONSUMED, row=row)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
