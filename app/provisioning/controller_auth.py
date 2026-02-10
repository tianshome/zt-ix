"""Helpers for resolving self-hosted controller authentication tokens."""

from __future__ import annotations

from pathlib import Path

from app.config import AppSettings


def read_controller_auth_token_file(token_file: str) -> str:
    source = token_file.strip()
    if not source:
        raise ValueError("controller auth token file path cannot be empty")

    try:
        token = Path(source).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(
            f"failed to read controller auth token file: {source}: {exc}"
        ) from exc

    if not token:
        raise ValueError(f"controller auth token file is empty: {source}")
    return token


def resolve_controller_auth_token(settings: AppSettings) -> str:
    token_file = settings.zt_controller_auth_token_file.strip()
    if token_file:
        return read_controller_auth_token_file(token_file)

    token = settings.zt_controller_auth_token.strip()
    if not token:
        raise ValueError(
            "ZT_CONTROLLER_AUTH_TOKEN is required when ZT_PROVIDER=self_hosted_controller"
        )
    return token
