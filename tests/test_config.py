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
