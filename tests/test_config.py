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
