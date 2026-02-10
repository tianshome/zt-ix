"""Application configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


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
    redis_url: str = "redis://localhost:6379/0"
    zt_provider: str = "central"
    zt_central_base_url: str = "https://api.zerotier.com/api/v1"
    zt_central_api_token: str = ""
    zt_controller_base_url: str = "http://127.0.0.1:9993/controller"
    zt_controller_auth_token: str = ""
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
    def from_env(cls) -> AppSettings:
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        secure_default = app_env == "production"

        scopes_raw = os.getenv("PEERINGDB_SCOPES", "openid profile email networks")
        scopes = _normalize_peeringdb_scopes(scopes_raw)
        route_server_hosts = _parse_csv_list(os.getenv("ROUTE_SERVER_HOSTS", ""))

        return cls(
            app_env=app_env,
            app_secret_key=os.getenv("APP_SECRET_KEY", "change-me"),
            session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "zt_ix_session"),
            session_cookie_max_age_seconds=_env_int("SESSION_COOKIE_MAX_AGE_SECONDS", 8 * 60 * 60),
            session_cookie_secure=_env_bool("SESSION_COOKIE_SECURE", secure_default),
            oauth_state_ttl_seconds=_env_int("OAUTH_STATE_TTL_SECONDS", 10 * 60),
            peeringdb_client_id=os.getenv("PEERINGDB_CLIENT_ID", ""),
            peeringdb_client_secret=os.getenv("PEERINGDB_CLIENT_SECRET", ""),
            peeringdb_redirect_uri=os.getenv(
                "PEERINGDB_REDIRECT_URI",
                "http://localhost:8000/auth/callback",
            ),
            peeringdb_authorization_url=os.getenv(
                "PEERINGDB_AUTHORIZATION_URL",
                "https://auth.peeringdb.com/oauth2/authorize/",
            ),
            peeringdb_token_url=os.getenv(
                "PEERINGDB_TOKEN_URL",
                "https://auth.peeringdb.com/oauth2/token/",
            ),
            peeringdb_profile_url=os.getenv(
                "PEERINGDB_PROFILE_URL",
                "https://auth.peeringdb.com/profile/v1",
            ),
            peeringdb_scopes=scopes,
            peeringdb_http_timeout_seconds=_env_float("PEERINGDB_HTTP_TIMEOUT_SECONDS", 10.0),
            local_auth_enabled=_env_bool("LOCAL_AUTH_ENABLED", True),
            local_auth_password_min_length=max(
                8,
                _env_int("LOCAL_AUTH_PASSWORD_MIN_LENGTH", 12),
            ),
            local_auth_pbkdf2_iterations=max(
                100_000,
                _env_int("LOCAL_AUTH_PBKDF2_ITERATIONS", 390_000),
            ),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            zt_provider=os.getenv("ZT_PROVIDER", "central").strip().lower(),
            zt_central_base_url=os.getenv("ZT_CENTRAL_BASE_URL", "https://api.zerotier.com/api/v1"),
            zt_central_api_token=os.getenv("ZT_CENTRAL_API_TOKEN", ""),
            zt_controller_base_url=os.getenv(
                "ZT_CONTROLLER_BASE_URL",
                "http://127.0.0.1:9993/controller",
            ),
            zt_controller_auth_token=os.getenv("ZT_CONTROLLER_AUTH_TOKEN", ""),
            route_server_hosts=route_server_hosts,
            route_server_ssh_user=os.getenv("ROUTE_SERVER_SSH_USER", "root").strip(),
            route_server_ssh_port=max(1, _env_int("ROUTE_SERVER_SSH_PORT", 22)),
            route_server_ssh_private_key_path=os.getenv(
                "ROUTE_SERVER_SSH_PRIVATE_KEY_PATH",
                "",
            ).strip(),
            route_server_ssh_connect_timeout_seconds=max(
                1.0,
                _env_float("ROUTE_SERVER_SSH_CONNECT_TIMEOUT_SECONDS", 10.0),
            ),
            route_server_ssh_strict_host_key=_env_bool("ROUTE_SERVER_SSH_STRICT_HOST_KEY", True),
            route_server_ssh_known_hosts_file=os.getenv(
                "ROUTE_SERVER_SSH_KNOWN_HOSTS_FILE",
                "",
            ).strip(),
            route_server_remote_config_dir=os.getenv(
                "ROUTE_SERVER_REMOTE_CONFIG_DIR",
                "/etc/bird/ztix-peers.d",
            ).strip()
            or "/etc/bird/ztix-peers.d",
            route_server_local_asn=max(1, _env_int("ROUTE_SERVER_LOCAL_ASN", 65000)),
        )


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return float(raw)
    except ValueError:
        return default


def _normalize_peeringdb_scopes(scopes_raw: str) -> tuple[str, ...]:
    parsed = [scope.strip() for scope in scopes_raw.split() if scope.strip()]
    if "openid" not in parsed:
        parsed.insert(0, "openid")

    normalized: list[str] = []
    seen: set[str] = set()
    for scope in parsed:
        if scope in seen:
            continue
        seen.add(scope)
        normalized.append(scope)
    return tuple(normalized)


def _parse_csv_list(value: str) -> tuple[str, ...]:
    parsed = [item.strip() for item in value.split(",") if item.strip()]
    deduped: list[str] = []
    seen: set[str] = set()
    for item in parsed:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return tuple(deduped)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings.from_env()
