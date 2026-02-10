from __future__ import annotations

import pytest

from app.config import AppSettings


def test_from_env_injects_openid_scope_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PEERINGDB_SCOPES", "profile email networks")

    settings = AppSettings.from_env()

    assert settings.peeringdb_scopes == ("openid", "profile", "email", "networks")
    assert settings.peeringdb_scope_param == "openid profile email networks"


def test_from_env_deduplicates_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PEERINGDB_SCOPES", "openid profile email openid networks profile")

    settings = AppSettings.from_env()

    assert settings.peeringdb_scopes == ("openid", "profile", "email", "networks")


def test_from_env_reads_local_auth_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_AUTH_ENABLED", "false")
    monkeypatch.setenv("LOCAL_AUTH_PASSWORD_MIN_LENGTH", "14")
    monkeypatch.setenv("LOCAL_AUTH_PBKDF2_ITERATIONS", "420000")

    settings = AppSettings.from_env()

    assert settings.local_auth_enabled is False
    assert settings.local_auth_password_min_length == 14
    assert settings.local_auth_pbkdf2_iterations == 420000


def test_from_env_clamps_local_auth_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_AUTH_PASSWORD_MIN_LENGTH", "2")
    monkeypatch.setenv("LOCAL_AUTH_PBKDF2_ITERATIONS", "10")

    settings = AppSettings.from_env()

    assert settings.local_auth_password_min_length == 8
    assert settings.local_auth_pbkdf2_iterations == 100000


def test_from_env_reads_provisioning_provider_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://example:6379/9")
    monkeypatch.setenv("ZT_PROVIDER", "self_hosted_controller")
    monkeypatch.setenv("ZT_CENTRAL_BASE_URL", "https://central.example/api")
    monkeypatch.setenv("ZT_CENTRAL_API_TOKEN", "central-secret")
    monkeypatch.setenv("ZT_CONTROLLER_BASE_URL", "http://controller.example:9993/controller")
    monkeypatch.setenv("ZT_CONTROLLER_AUTH_TOKEN", "controller-secret")

    settings = AppSettings.from_env()

    assert settings.redis_url == "redis://example:6379/9"
    assert settings.zt_provider == "self_hosted_controller"
    assert settings.zt_central_base_url == "https://central.example/api"
    assert settings.zt_central_api_token == "central-secret"
    assert settings.zt_controller_base_url == "http://controller.example:9993/controller"
    assert settings.zt_controller_auth_token == "controller-secret"
