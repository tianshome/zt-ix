"""Common FastAPI dependencies."""

from __future__ import annotations

import uuid
from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from app.config import AppSettings
from app.integrations.peeringdb import PeeringDBClientProtocol


def get_app_settings(request: Request) -> AppSettings:
    return cast(AppSettings, request.app.state.settings)


def get_peeringdb_client(request: Request) -> PeeringDBClientProtocol:
    return cast(PeeringDBClientProtocol, request.app.state.peeringdb_client)


def get_db_session(request: Request) -> Generator[Session]:
    session_factory = cast(sessionmaker[Session], request.app.state.session_maker)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@dataclass(frozen=True, slots=True)
class SessionActor:
    user_id: uuid.UUID
    is_admin: bool


def get_session_actor(request: Request) -> SessionActor:
    raw_user_id = request.session.get("user_id")
    if not isinstance(raw_user_id, str):
        raise HTTPException(status_code=401, detail="authentication required")

    try:
        user_id = uuid.UUID(raw_user_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid session user") from exc

    is_admin = bool(request.session.get("is_admin", False))
    return SessionActor(user_id=user_id, is_admin=is_admin)


def get_admin_session_actor(
    actor: Annotated[SessionActor, Depends(get_session_actor)],
) -> SessionActor:
    if not actor.is_admin:
        raise HTTPException(status_code=403, detail="admin role required")
    return actor
