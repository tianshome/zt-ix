"""Common FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Generator
from typing import cast

from fastapi import Request
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
