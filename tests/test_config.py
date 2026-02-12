from __future__ import annotations

from pathlib import Path

import pytest

from app.config import AppSettings, get_settings


def _write_runtime_config(tmp_path: Path, content: str) -> Path:
    runtime_config = tmp_path / "runtime-config.yaml"
    runtime_config.write_text(content, encoding="utf-8")
    return runtime_config


def test_from_yaml_injects_openid_scope_when_missing(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
peeringdb:
  scopes:
    - profile
    - email
    - networks
""",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.peeringdb_scopes == ("openid", "profile", "email", "networks")
    assert settings.peeringdb_scope_param == "openid profile email networks"


def test_from_yaml_deduplicates_scopes(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
peeringdb:
  scopes: [openid, profile, email, openid, networks, profile]
""",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.peeringdb_scopes == ("openid", "profile", "email", "networks")


def test_from_yaml_reads_local_auth_settings(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
auth:
  local_auth:
    enabled: false
    password_min_length: 14
    pbkdf2_iterations: 420000
""",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.local_auth_enabled is False
    assert settings.local_auth_password_min_length == 14
    assert settings.local_auth_pbkdf2_iterations == 420000


def test_from_yaml_clamps_local_auth_bounds(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
auth:
  local_auth:
    password_min_length: 2
    pbkdf2_iterations: 10
""",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.local_auth_password_min_length == 8
    assert settings.local_auth_pbkdf2_iterations == 100000


def test_from_yaml_reads_provisioning_provider_settings(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
redis:
  url: redis://example:6379/9
zerotier:
  provider: self_hosted_controller
  central:
    base_url: https://central.example/api
    api_token: central-secret
  self_hosted_controller:
    base_url: http://controller.example:9993/controller
    auth_token: controller-secret
    auth_token_file: /run/secrets/zt_controller_token
    lifecycle:
      required_network_suffixes: [abc123, 654321]
      required_network_ids: [abcdef0123456789, 0123456789abcdef]
      readiness_strict: true
      backup_dir: /var/backups/zt-ix-controller
      backup_retention_count: 21
      state_dir: /var/lib/zerotier-one
""",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.redis_url == "redis://example:6379/9"
    assert settings.zt_provider == "self_hosted_controller"
    assert settings.zt_central_base_url == "https://central.example/api"
    assert settings.zt_central_api_token == "central-secret"
    assert settings.zt_controller_base_url == "http://controller.example:9993/controller"
    assert settings.zt_controller_auth_token == "controller-secret"
    assert settings.zt_controller_auth_token_file == "/run/secrets/zt_controller_token"
    assert settings.zt_controller_required_network_suffixes == (
        "abc123",
        "654321",
    )
    assert settings.zt_controller_required_network_ids == (
        "abcdef0123456789",
        "0123456789abcdef",
    )
    assert settings.zt_controller_readiness_strict is True
    assert settings.zt_controller_backup_dir == "/var/backups/zt-ix-controller"
    assert settings.zt_controller_backup_retention_count == 21
    assert settings.zt_controller_state_dir == "/var/lib/zerotier-one"


def test_from_yaml_reads_workflow_approval_mode_from_runtime_config(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        "workflow:\n  approval_mode: policy_auto\n",
    )

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.runtime_config_path == str(runtime_config)
    assert settings.workflow_approval_mode == "policy_auto"


def test_from_yaml_defaults_workflow_approval_mode_when_runtime_config_missing(
    tmp_path: Path,
) -> None:
    runtime_config = tmp_path / "missing-runtime-config.yaml"

    settings = AppSettings.from_yaml(str(runtime_config))

    assert settings.workflow_approval_mode == "manual_admin"


def test_from_yaml_rejects_invalid_workflow_approval_mode(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        "workflow:\n  approval_mode: maybe_later\n",
    )

    with pytest.raises(ValueError, match="workflow.approval_mode"):
        AppSettings.from_yaml(str(runtime_config))


def test_from_env_alias_uses_yaml_path(tmp_path: Path) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        "workflow:\n  approval_mode: policy_auto\n",
    )

    settings = AppSettings.from_env(str(runtime_config))

    assert settings.workflow_approval_mode == "policy_auto"


def test_get_settings_applies_controller_base_url_env_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_config = _write_runtime_config(
        tmp_path,
        """
zerotier:
  provider: self_hosted_controller
  self_hosted_controller:
    base_url: http://127.0.0.1:9993/controller
""",
    )
    monkeypatch.setenv("ZTIX_RUNTIME_CONFIG_PATH", str(runtime_config))
    monkeypatch.setenv(
        "ZT_CONTROLLER_BASE_URL",
        "http://zerotier-controller:9993/controller",
    )
    get_settings.cache_clear()
    try:
        settings = get_settings()
    finally:
        get_settings.cache_clear()

    assert settings.runtime_config_path == str(runtime_config)
    assert settings.zt_controller_base_url == "http://zerotier-controller:9993/controller"
