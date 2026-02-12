"""Application configuration loading."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast

import os
import yaml

ApprovalMode = Literal[
    "manual_admin",
    "policy_auto",
]
APPROVAL_MODE_MANUAL_ADMIN: ApprovalMode = "manual_admin"
APPROVAL_MODE_POLICY_AUTO: ApprovalMode = "policy_auto"


@dataclass(frozen=True, slots=True)
class AppSettings:
    app_env: str
    app_secret_key: str
    session_cookie_name: str
    session_cookie_max_age_seconds: int
    session_cookie_secure: bool
    oauth_state_ttl_seconds: int
    peeringdb_client_id: str
    peeringdb_client_secret: str
    peeringdb_redirect_uri: str
    peeringdb_authorization_url: str
    peeringdb_token_url: str
    peeringdb_profile_url: str
    peeringdb_scopes: tuple[str, ...]
    peeringdb_http_timeout_seconds: float
    local_auth_enabled: bool
    local_auth_password_min_length: int
    local_auth_pbkdf2_iterations: int
    runtime_config_path: str = "runtime-config.yaml"
    workflow_approval_mode: ApprovalMode = APPROVAL_MODE_MANUAL_ADMIN
    redis_url: str = "redis://localhost:6379/0"
    zt_provider: str = "central"
    zt_central_base_url: str = "https://api.zerotier.com/api/v1"
    zt_central_api_token: str = ""
    zt_controller_base_url: str = "http://127.0.0.1:9993/controller"
    zt_controller_auth_token: str = ""
    zt_controller_auth_token_file: str = ""
    zt_controller_required_network_ids: tuple[str, ...] = ()
    zt_controller_readiness_strict: bool = True
    zt_controller_backup_dir: str = "/var/backups/zt-ix-controller"
    zt_controller_backup_retention_count: int = 14
    zt_controller_state_dir: str = "/var/lib/zerotier-one"
    route_server_hosts: tuple[str, ...] = ()
    route_server_ssh_user: str = "root"
    route_server_ssh_port: int = 22
    route_server_ssh_private_key_path: str = ""
    route_server_ssh_connect_timeout_seconds: float = 10.0
    route_server_ssh_strict_host_key: bool = True
    route_server_ssh_known_hosts_file: str = ""
    route_server_remote_config_dir: str = "/etc/bird/ztix-peers.d"
    route_server_local_asn: int = 65000

    @property
    def peeringdb_scope_param(self) -> str:
        return " ".join(self.peeringdb_scopes)

    @classmethod
    def from_yaml(cls, runtime_config_path: str = "runtime-config.yaml") -> AppSettings:
        normalized_path = runtime_config_path.strip() or "runtime-config.yaml"
        config = _load_runtime_config(normalized_path)

        app_cfg = cast(dict[str, Any], config.get("app", {}))
        session_cfg = cast(dict[str, Any], config.get("session", {}))
        auth_cfg = cast(dict[str, Any], config.get("auth", {}))
        local_auth_cfg = cast(dict[str, Any], auth_cfg.get("local_auth", {}))
        peeringdb_cfg = cast(dict[str, Any], config.get("peeringdb", {}))
        redis_cfg = cast(dict[str, Any], config.get("redis", {}))
        zerotier_cfg = cast(dict[str, Any], config.get("zerotier", {}))
        central_cfg = cast(dict[str, Any], zerotier_cfg.get("central", {}))
        controller_cfg = cast(
            dict[str, Any], zerotier_cfg.get("self_hosted_controller", {})
        )
        lifecycle_cfg = cast(dict[str, Any], controller_cfg.get("lifecycle", {}))
        route_servers_cfg = cast(dict[str, Any], config.get("route_servers", {}))
        route_servers_ssh_cfg = cast(dict[str, Any], route_servers_cfg.get("ssh", {}))

        app_env = str(app_cfg.get("env", "development")).lower()
        peeringdb_scopes = _normalize_peeringdb_scopes(
            tuple(
                cast(
                    list[str],
                    peeringdb_cfg.get(
                        "scopes", ["openid", "profile", "email", "networks"]
                    ),
                )
            )
        )
        workflow_approval_mode = _resolve_workflow_approval_mode(config)

        return cls(
            app_env=app_env,
            app_secret_key=str(app_cfg.get("secret_key", "change-me")),
            session_cookie_name=str(session_cfg.get("cookie_name", "zt_ix_session")),
            session_cookie_max_age_seconds=int(
                session_cfg.get("cookie_max_age_seconds", 8 * 60 * 60)
            ),
            session_cookie_secure=bool(
                session_cfg.get("cookie_secure", app_env == "production")
            ),
            oauth_state_ttl_seconds=int(
                auth_cfg.get("oauth_state_ttl_seconds", 10 * 60)
            ),
            peeringdb_client_id=str(peeringdb_cfg.get("client_id", "")),
            peeringdb_client_secret=str(peeringdb_cfg.get("client_secret", "")),
            peeringdb_redirect_uri=str(
                peeringdb_cfg.get("redirect_uri", "http://localhost:5173/auth/callback")
            ),
            peeringdb_authorization_url=str(
                peeringdb_cfg.get(
                    "authorization_url", "https://auth.peeringdb.com/oauth2/authorize/"
                )
            ),
            peeringdb_token_url=str(
                peeringdb_cfg.get(
                    "token_url", "https://auth.peeringdb.com/oauth2/token/"
                )
            ),
            peeringdb_profile_url=str(
                peeringdb_cfg.get(
                    "profile_url", "https://auth.peeringdb.com/profile/v1"
                )
            ),
            peeringdb_scopes=peeringdb_scopes,
            peeringdb_http_timeout_seconds=float(
                peeringdb_cfg.get("http_timeout_seconds", 10.0)
            ),
            local_auth_enabled=bool(local_auth_cfg.get("enabled", True)),
            local_auth_password_min_length=max(
                8,
                int(local_auth_cfg.get("password_min_length", 12)),
            ),
            local_auth_pbkdf2_iterations=max(
                100_000,
                int(local_auth_cfg.get("pbkdf2_iterations", 390_000)),
            ),
            runtime_config_path=normalized_path,
            workflow_approval_mode=workflow_approval_mode,
            redis_url=str(redis_cfg.get("url", "redis://localhost:6379/0")),
            zt_provider=str(zerotier_cfg.get("provider", "central")).lower(),
            zt_central_base_url=str(
                central_cfg.get("base_url", "https://api.zerotier.com/api/v1")
            ),
            zt_central_api_token=str(central_cfg.get("api_token", "")),
            zt_controller_base_url=str(
                controller_cfg.get("base_url", "http://127.0.0.1:9993/controller")
            ),
            zt_controller_auth_token=os.environ.get("ZT_CONTROLLER_AUTH_TOKEN", ""),
            zt_controller_auth_token_file=str(
                controller_cfg.get("auth_token_file", "")
            ),
            zt_controller_required_network_ids=tuple(
                cast(list[str], lifecycle_cfg.get("required_network_ids", []))
            ),
            zt_controller_readiness_strict=bool(
                lifecycle_cfg.get("readiness_strict", True)
            ),
            zt_controller_backup_dir=str(
                lifecycle_cfg.get("backup_dir", "/var/backups/zt-ix-controller")
            ),
            zt_controller_backup_retention_count=max(
                1,
                int(lifecycle_cfg.get("backup_retention_count", 14)),
            ),
            zt_controller_state_dir=str(
                lifecycle_cfg.get("state_dir", "/var/lib/zerotier-one")
            ),
            route_server_hosts=tuple(
                cast(list[str], route_servers_cfg.get("hosts", []))
            ),
            route_server_ssh_user=str(route_servers_ssh_cfg.get("user", "root")),
            route_server_ssh_port=max(1, int(route_servers_ssh_cfg.get("port", 22))),
            route_server_ssh_private_key_path=str(
                route_servers_ssh_cfg.get("private_key_path", "")
            ),
            route_server_ssh_connect_timeout_seconds=max(
                1.0,
                float(route_servers_ssh_cfg.get("connect_timeout_seconds", 10.0)),
            ),
            route_server_ssh_strict_host_key=bool(
                route_servers_ssh_cfg.get("strict_host_key", True)
            ),
            route_server_ssh_known_hosts_file=str(
                route_servers_ssh_cfg.get("known_hosts_file", "")
            ),
            route_server_remote_config_dir=str(
                route_servers_cfg.get("remote_config_dir", "/etc/bird/ztix-peers.d")
            ),
            route_server_local_asn=max(
                1, int(route_servers_cfg.get("local_asn", 65000))
            ),
        )

    @classmethod
    def from_env(cls, runtime_config_path: str = "runtime-config.yaml") -> AppSettings:
        return cls.from_yaml(runtime_config_path=runtime_config_path)


def _load_runtime_config(runtime_config_path: str) -> dict[str, Any]:
    path = Path(runtime_config_path)
    if not path.exists() or not path.is_file():
        return {}

    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(parsed, dict):
        return parsed
    return {}


def _normalize_peeringdb_scopes(scopes: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    if "openid" not in scopes:
        normalized.append("openid")
        seen.add("openid")

    for scope in scopes:
        normalized_scope = scope.strip()
        if not normalized_scope or normalized_scope in seen:
            continue
        seen.add(normalized_scope)
        normalized.append(normalized_scope)
    return tuple(normalized)


def _resolve_workflow_approval_mode(config: dict[str, Any]) -> ApprovalMode:
    workflow_cfg = cast(dict[str, Any], config.get("workflow", {}))
    normalized_mode = str(
        workflow_cfg.get("approval_mode", APPROVAL_MODE_MANUAL_ADMIN)
    ).lower()

    if normalized_mode == APPROVAL_MODE_MANUAL_ADMIN:
        return APPROVAL_MODE_MANUAL_ADMIN
    if normalized_mode == APPROVAL_MODE_POLICY_AUTO:
        return APPROVAL_MODE_POLICY_AUTO

    raise ValueError(
        "unsupported workflow.approval_mode in runtime config: "
        f"{normalized_mode!r}; expected one of "
        f"{APPROVAL_MODE_MANUAL_ADMIN!r}, {APPROVAL_MODE_POLICY_AUTO!r}"
    )


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings.from_yaml()
