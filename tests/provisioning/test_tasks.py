from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import pytest

from app.config import AppSettings
from app.provisioning import service, tasks


def test_enqueue_provision_join_request_dispatches_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_delay(request_id: str) -> None:
        captured["request_id"] = request_id
        captured["broker_url"] = tasks.celery_app.conf.broker_url

    monkeypatch.setattr(tasks.provision_join_request_task, "delay", fake_delay)
    request_id = uuid.uuid4()
    settings = _settings(redis_url="memory://", zt_provider="central")

    tasks.enqueue_provision_join_request(request_id=request_id, settings=settings)

    assert captured["request_id"] == str(request_id)
    assert captured["broker_url"] == "memory://"


def test_provision_task_uses_runtime_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    request_id = uuid.uuid4()
    captured: dict[str, Any] = {}
    runtime_settings = _settings(zt_provider="self_hosted_controller")

    monkeypatch.setattr(tasks, "get_settings", lambda: runtime_settings)

    def fake_process(*, request_id: uuid.UUID, settings: AppSettings) -> None:
        captured["request_id"] = request_id
        captured["provider"] = settings.zt_provider
        captured["controller_token"] = settings.zt_controller_auth_token

    monkeypatch.setattr(tasks, "process_join_request_provisioning", fake_process)

    tasks.provision_join_request_task(str(request_id))

    assert captured["request_id"] == request_id
    assert captured["provider"] == "self_hosted_controller"
    assert captured["controller_token"] == "controller-token"


def test_process_join_request_provisioning_resolves_provider_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = uuid.uuid4()
    settings = _settings(zt_provider="self_hosted_controller")
    captured: dict[str, Any] = {}

    class DummyProvider:
        provider_name = "dummy"

        def validate_network(self, zt_network_id: str) -> bool:
            raise AssertionError(f"unexpected validate_network call: {zt_network_id}")

        def authorize_member(
            self,
            *,
            zt_network_id: str,
            node_id: str,
            asn: int,
            request_id: uuid.UUID,
        ) -> Any:
            raise AssertionError(
                f"unexpected authorize_member call for {zt_network_id} {node_id} {asn} {request_id}"
            )

    class DummySessionContext:
        def __enter__(self) -> object:
            return object()

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            traceback: Any,
        ) -> None:
            return None

    monkeypatch.setattr(service, "SessionLocal", lambda: DummySessionContext())

    def fake_create_provider(received: AppSettings) -> DummyProvider:
        captured["provider_mode"] = received.zt_provider
        return DummyProvider()

    monkeypatch.setattr(service, "create_provisioning_provider", fake_create_provider)

    def fake_process_with_provider(
        *,
        db_session: object,
        request_id: uuid.UUID,
        provider: DummyProvider,
    ) -> None:
        captured["request_id"] = request_id
        captured["provider_name"] = provider.provider_name
        captured["db_session_type"] = type(db_session).__name__

    monkeypatch.setattr(
        service,
        "process_join_request_provisioning_with_provider",
        fake_process_with_provider,
    )

    service.process_join_request_provisioning(request_id=request_id, settings=settings)

    assert captured["provider_mode"] == "self_hosted_controller"
    assert captured["request_id"] == request_id
    assert captured["provider_name"] == "dummy"
    assert captured["db_session_type"] == "object"


def _settings(**overrides: Any) -> AppSettings:
    base = AppSettings(
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
        zt_provider="central",
        zt_central_base_url="https://api.zerotier.com/api/v1",
        zt_central_api_token="central-token",
        zt_controller_base_url="http://127.0.0.1:9993/controller",
        zt_controller_auth_token="controller-token",
    )
    return replace(base, **overrides)
