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

    @property
    def peeringdb_scope_param(self) -> str:
        return " ".join(self.peeringdb_scopes)

    @classmethod
    def from_env(cls) -> AppSettings:
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        secure_default = app_env == "production"

        scopes_raw = os.getenv("PEERINGDB_SCOPES", "openid profile email networks")
        scopes = _normalize_peeringdb_scopes(scopes_raw)

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


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings.from_env()
