from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import AppSettings
from app.db import models as _models  # noqa: F401
from app.db.base import Base
from app.integrations.peeringdb import (
    PeeringDBNetwork,
    PeeringDBTokenResponse,
    PeeringDBUserProfile,
)
from app.main import create_app


@dataclass(slots=True)
class StubPeeringDBClient:
    token_result: PeeringDBTokenResponse | Exception = field(
        default_factory=lambda: PeeringDBTokenResponse(access_token="access-token", id_token=None)
    )
    profile_result: PeeringDBUserProfile | Exception = field(
        default_factory=lambda: PeeringDBUserProfile(
            peeringdb_user_id=1001,
            username="operator",
            full_name="Operator Example",
            email="operator@example.net",
            networks=(
                PeeringDBNetwork(asn=64512, net_id=10, net_name="ExampleNet", perms=15),
            ),
        )
    )
    token_calls: list[dict[str, str]] = field(default_factory=list)
    profile_calls: list[str] = field(default_factory=list)

    async def exchange_code_for_tokens(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> PeeringDBTokenResponse:
        self.token_calls.append(
            {
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
            }
        )
        if isinstance(self.token_result, Exception):
            raise self.token_result
        return self.token_result

    async def fetch_profile(self, *, access_token: str) -> PeeringDBUserProfile:
        self.profile_calls.append(access_token)
        if isinstance(self.profile_result, Exception):
            raise self.profile_result
        return self.profile_result


@pytest.fixture()
def workflow_settings() -> AppSettings:
    return AppSettings(
        app_env="test",
        app_secret_key="test-secret",
        session_cookie_name="zt_ix_session",
        session_cookie_max_age_seconds=3600,
        session_cookie_secure=False,
        oauth_state_ttl_seconds=300,
        peeringdb_client_id="client-id",
        peeringdb_client_secret="client-secret",
        peeringdb_redirect_uri="http://testserver/auth/callback",
        peeringdb_authorization_url="https://auth.peeringdb.com/oauth2/authorize/",
        peeringdb_token_url="https://auth.peeringdb.com/oauth2/token/",
        peeringdb_profile_url="https://auth.peeringdb.com/profile/v1",
        peeringdb_scopes=("openid", "profile", "email", "networks"),
        peeringdb_http_timeout_seconds=2.0,
        local_auth_enabled=True,
        local_auth_password_min_length=12,
        local_auth_pbkdf2_iterations=100_000,
        redis_url="memory://",
        zt_provider="central",
        zt_central_base_url="https://api.zerotier.com/api/v1",
        zt_central_api_token="test-central-token",
        zt_controller_base_url="http://127.0.0.1:9993/controller",
        zt_controller_auth_token="test-controller-token",
    )


@pytest.fixture()
def db_engine() -> Generator[Engine]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: Any, _: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def session_factory(db_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(
        bind=db_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


@pytest.fixture()
def stub_peeringdb_client() -> StubPeeringDBClient:
    return StubPeeringDBClient()


@pytest.fixture()
def test_app(
    workflow_settings: AppSettings,
    session_factory: sessionmaker[Session],
    stub_peeringdb_client: StubPeeringDBClient,
) -> FastAPI:
    app = create_app(settings=workflow_settings)
    app.state.session_maker = session_factory
    app.state.peeringdb_client = stub_peeringdb_client
    return app


@pytest.fixture()
def client(test_app: FastAPI) -> Generator[TestClient]:
    with TestClient(test_app) as test_client:
        yield test_client


@pytest.fixture()
def db_session(session_factory: sessionmaker[Session]) -> Generator[Session]:
    with session_factory() as session:
        yield session
