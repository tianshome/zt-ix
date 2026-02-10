from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.config import AppSettings
from app.main import create_app
from app.provisioning.controller_lifecycle import ControllerLifecycleGateError


def test_startup_preflight_fails_closed_when_strict_enabled(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    settings = replace(_settings(), zt_controller_readiness_strict=True)
    app = create_app(settings=settings)
    app.state.session_maker = session_factory

    monkeypatch.setattr("app.main.create_controller_lifecycle_manager", lambda _: object())

    def fake_preflight(**_: Any) -> None:
        raise ControllerLifecycleGateError(
            "controller preflight failed",
            remediation="fix controller",
        )

    monkeypatch.setattr("app.main.run_controller_lifecycle_preflight", fake_preflight)

    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_startup_preflight_uses_non_strict_mode_when_configured(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    settings = replace(_settings(), zt_controller_readiness_strict=False)
    app = create_app(settings=settings)
    app.state.session_maker = session_factory

    monkeypatch.setattr("app.main.create_controller_lifecycle_manager", lambda _: object())
    captured: dict[str, Any] = {}

    def fake_preflight(**kwargs: Any) -> None:
        captured["strict_fail_closed"] = kwargs["strict_fail_closed"]
        return None

    monkeypatch.setattr("app.main.run_controller_lifecycle_preflight", fake_preflight)

    with TestClient(app) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert captured["strict_fail_closed"] is False


def _settings() -> AppSettings:
    return AppSettings(
        app_env="test",
        app_secret_key="secret",
        session_cookie_name="zt_ix_session",
        session_cookie_max_age_seconds=3600,
        session_cookie_secure=False,
        oauth_state_ttl_seconds=600,
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
        zt_provider="self_hosted_controller",
        zt_central_base_url="https://api.zerotier.com/api/v1",
        zt_central_api_token="central-token",
        zt_controller_base_url="http://127.0.0.1:9993/controller",
        zt_controller_auth_token="controller-token",
    )
