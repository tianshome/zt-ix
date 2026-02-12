"""SPA authentication API routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.auth import (
    generate_nonce,
    generate_pkce_verifier,
    generate_state,
    normalize_login_username,
    pkce_code_challenge,
    verify_password,
)
from app.config import AppSettings
from app.db.models import AppUser
from app.dependencies import get_app_settings, get_db_session, get_peeringdb_client
from app.integrations.peeringdb import (
    PeeringDBClientError,
    PeeringDBClientProtocol,
    PeeringDBNonceValidationError,
    validate_id_token_nonce,
)
from app.repositories.audit_events import AuditEventRepository
from app.repositories.local_credentials import LocalCredentialRepository
from app.repositories.oauth_state_nonces import (
    OauthStateConsumeStatus,
    OauthStateNonceRepository,
)
from app.repositories.user_asns import UserAsnRecord, UserAsnRepository
from app.repositories.users import UserRepository

router = APIRouter(tags=["auth"])
SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]
DbSessionDep = Annotated[Session, Depends(get_db_session)]
PeeringDBClientDep = Annotated[PeeringDBClientProtocol, Depends(get_peeringdb_client)]


class LocalLoginPayload(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        return normalize_login_username(value)

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        if not value:
            raise ValueError("password is required")
        return value


class PeeringDBCallbackPayload(BaseModel):
    code: str | None = None
    state: str | None = None
    error: str | None = None

    @field_validator("code", "state", "error")
    @classmethod
    def _normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


@router.post("/api/v1/auth/peeringdb/start")
async def api_auth_peeringdb_start(
    settings: SettingsDep,
    db_session: DbSessionDep,
) -> JSONResponse:
    state = generate_state()
    nonce = generate_nonce()
    pkce_verifier = generate_pkce_verifier()
    code_challenge = pkce_code_challenge(pkce_verifier)
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.oauth_state_ttl_seconds)

    oauth_repo = OauthStateNonceRepository(db_session)
    audit_repo = AuditEventRepository(db_session)
    oauth_repo.create(
        state=state,
        nonce=nonce,
        pkce_verifier=pkce_verifier,
        redirect_uri=settings.peeringdb_redirect_uri,
        expires_at=expires_at,
    )
    audit_repo.create_event(
        action="auth.login.started",
        target_type="oauth_state",
        target_id=state,
        metadata={"expires_at": expires_at.isoformat()},
    )
    db_session.commit()

    query_params = {
        "client_id": settings.peeringdb_client_id,
        "response_type": "code",
        "redirect_uri": settings.peeringdb_redirect_uri,
        "scope": settings.peeringdb_scope_param,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    authorization_url = f"{settings.peeringdb_authorization_url}?{urlencode(query_params)}"

    return _success_response(
        {
            "authorization_url": authorization_url,
            "state": state,
            "expires_at": expires_at.isoformat(),
            "redirect_uri": settings.peeringdb_redirect_uri,
            "scope": settings.peeringdb_scope_param,
        }
    )


@router.post("/api/v1/auth/peeringdb/callback")
async def api_auth_peeringdb_callback(
    request: Request,
    payload: PeeringDBCallbackPayload,
    peeringdb_client: PeeringDBClientDep,
    db_session: DbSessionDep,
) -> JSONResponse:
    audit_repo = AuditEventRepository(db_session)

    if payload.error:
        _audit_callback_failure(
            audit_repo,
            error_code="oauth_error",
            target_state=payload.state,
            metadata={"oauth_error": payload.error},
        )
        db_session.commit()
        return _error_response(
            status_code=400,
            code="oauth_error",
            message="Login was canceled or rejected by PeeringDB.",
            details={"oauth_error": payload.error},
        )

    if not payload.code or not payload.state:
        _audit_callback_failure(
            audit_repo,
            error_code="missing_code_or_state",
            target_state=payload.state,
        )
        db_session.commit()
        return _error_response(
            status_code=400,
            code="missing_code_or_state",
            message="Callback is missing required OAuth parameters.",
        )

    oauth_repo = OauthStateNonceRepository(db_session)
    consume_result = oauth_repo.consume_state(state=payload.state)

    if consume_result.status is OauthStateConsumeStatus.MISSING:
        _audit_callback_failure(audit_repo, error_code="invalid_state", target_state=payload.state)
        db_session.commit()
        return _error_response(
            status_code=400,
            code="invalid_state",
            message="Login session is invalid or has already been used.",
            details={"detail_code": "state_missing_or_reused"},
        )

    if consume_result.status is OauthStateConsumeStatus.EXPIRED:
        _audit_callback_failure(audit_repo, error_code="expired_state", target_state=payload.state)
        db_session.commit()
        return _error_response(
            status_code=400,
            code="expired_state",
            message="Login session expired before callback completed.",
            details={"detail_code": "state_expired"},
        )

    state_row = consume_result.row
    if state_row is None:
        _audit_callback_failure(audit_repo, error_code="invalid_state", target_state=payload.state)
        db_session.commit()
        return _error_response(
            status_code=400,
            code="invalid_state",
            message="Login session is invalid or has already been used.",
            details={"detail_code": "state_missing_or_reused"},
        )

    try:
        token_response = await peeringdb_client.exchange_code_for_tokens(
            code=payload.code,
            code_verifier=state_row.pkce_verifier,
            redirect_uri=state_row.redirect_uri,
        )
        validate_id_token_nonce(id_token=token_response.id_token, expected_nonce=state_row.nonce)
        profile = await peeringdb_client.fetch_profile(access_token=token_response.access_token)
    except PeeringDBNonceValidationError as exc:
        detail_code = _nonce_error_detail(exc)
        _audit_callback_failure(
            audit_repo,
            error_code="invalid_nonce",
            target_state=payload.state,
            metadata={"detail": str(exc), "detail_code": detail_code},
        )
        db_session.commit()
        return _error_response(
            status_code=400,
            code="invalid_nonce",
            message="OIDC nonce validation failed for the returned identity token.",
            details={"detail_code": detail_code},
        )
    except PeeringDBClientError as exc:
        _audit_callback_failure(
            audit_repo,
            error_code="upstream_auth_failure",
            target_state=payload.state,
            metadata={"detail": str(exc)},
        )
        db_session.commit()
        return _error_response(
            status_code=400,
            code="upstream_auth_failure",
            message="PeeringDB token or profile request failed.",
            details={"detail": str(exc)},
        )

    user_repo = UserRepository(db_session)
    user_asn_repo = UserAsnRepository(db_session)

    user = user_repo.upsert_peeringdb_user(
        peeringdb_user_id=profile.peeringdb_user_id,
        username=profile.username,
        full_name=profile.full_name,
        email=profile.email,
        is_admin=None,
    )

    asn_rows = user_asn_repo.replace_for_user(
        user.id,
        [
            UserAsnRecord(asn=network.asn, net_id=network.net_id, net_name=network.net_name)
            for network in profile.authorized_networks
        ],
    )

    request.session.clear()
    request.session.update(
        {
            "user_id": str(user.id),
            "peeringdb_user_id": profile.peeringdb_user_id,
            "is_admin": user.is_admin,
            "authenticated_at": datetime.now(UTC).isoformat(),
            "auth_mode": "peeringdb",
        }
    )

    audit_repo.create_event(
        action="auth.callback.succeeded",
        target_type="app_user",
        target_id=str(user.id),
        actor_user_id=user.id,
        metadata={
            "peeringdb_user_id": profile.peeringdb_user_id,
            "authorized_asn_count": len(asn_rows),
        },
    )
    if not asn_rows:
        audit_repo.create_event(
            action="auth.callback.no_eligible_asn",
            target_type="app_user",
            target_id=str(user.id),
            actor_user_id=user.id,
        )

    db_session.commit()
    return _success_response(
        {
            "auth": {
                "mode": "peeringdb",
                "authorized_asn_count": len(asn_rows),
                "has_eligible_asn": bool(asn_rows),
            },
            "user": _serialize_user_summary(user),
        }
    )


@router.post("/api/v1/auth/local/login")
async def api_auth_local_login(
    request: Request,
    payload: LocalLoginPayload,
    settings: SettingsDep,
    db_session: DbSessionDep,
) -> JSONResponse:
    audit_repo = AuditEventRepository(db_session)
    if not settings.local_auth_enabled:
        _audit_local_login_failure(
            audit_repo,
            login_username=payload.username,
            failure_code="local_auth_disabled",
        )
        db_session.commit()
        return _error_response(
            status_code=403,
            code="local_auth_disabled",
            message="Local login is disabled in this deployment.",
        )

    credential_repo = LocalCredentialRepository(db_session)
    credential = credential_repo.get_by_login_username(payload.username)

    if credential is None:
        _audit_local_login_failure(
            audit_repo,
            login_username=payload.username,
            failure_code="invalid_credentials",
        )
        db_session.commit()
        return _error_response(
            status_code=401,
            code="local_invalid_credentials",
            message="Invalid username or password.",
        )

    if not credential.is_enabled:
        _audit_local_login_failure(
            audit_repo,
            actor_user_id=credential.user_id,
            login_username=credential.login_username,
            failure_code="credential_disabled",
        )
        db_session.commit()
        return _error_response(
            status_code=403,
            code="local_credential_disabled",
            message="This local account is disabled. Contact support.",
            details={"detail_code": "contact_support"},
        )

    if not verify_password(password=payload.password, encoded_hash=credential.password_hash):
        _audit_local_login_failure(
            audit_repo,
            actor_user_id=credential.user_id,
            login_username=credential.login_username,
            failure_code="invalid_credentials",
        )
        db_session.commit()
        return _error_response(
            status_code=401,
            code="local_invalid_credentials",
            message="Invalid username or password.",
        )

    user = credential.user
    asn_rows = UserAsnRepository(db_session).list_by_user_id(user.id)
    if not asn_rows:
        audit_repo.create_event(
            action="auth.local_login.no_eligible_asn",
            target_type="app_user",
            target_id=str(user.id),
            actor_user_id=user.id,
            metadata={"login_username": credential.login_username},
        )

    credential_repo.touch_last_login(credential)
    request.session.clear()
    request.session.update(
        {
            "user_id": str(user.id),
            "peeringdb_user_id": user.peeringdb_user_id,
            "is_admin": user.is_admin,
            "authenticated_at": datetime.now(UTC).isoformat(),
            "auth_mode": "local",
        }
    )

    audit_repo.create_event(
        action="auth.local_login.succeeded",
        target_type="app_user",
        target_id=str(user.id),
        actor_user_id=user.id,
        metadata={
            "login_username": credential.login_username,
            "authorized_asn_count": len(asn_rows),
        },
    )
    db_session.commit()
    return _success_response(
        {
            "auth": {
                "mode": "local",
                "authorized_asn_count": len(asn_rows),
                "has_eligible_asn": bool(asn_rows),
            },
            "user": _serialize_user_summary(user),
        }
    )


@router.post("/api/v1/auth/logout")
async def api_auth_logout(
    request: Request,
    db_session: DbSessionDep,
) -> JSONResponse:
    actor_user_id = _session_user_id(request)
    if actor_user_id is None:
        return _error_response(
            status_code=401,
            code="unauthenticated",
            message="Authentication required.",
        )

    request.session.clear()
    AuditEventRepository(db_session).create_event(
        action="auth.logout",
        target_type="auth_session",
        target_id=str(actor_user_id),
        actor_user_id=actor_user_id,
    )
    db_session.commit()
    return _success_response({"logged_out": True})


def _session_user_id(request: Request) -> uuid.UUID | None:
    raw_user_id = request.session.get("user_id")
    if not isinstance(raw_user_id, str):
        return None

    try:
        return uuid.UUID(raw_user_id)
    except ValueError:
        return None


def _audit_callback_failure(
    audit_repo: AuditEventRepository,
    *,
    error_code: str,
    target_state: str | None,
    metadata: dict[str, str] | None = None,
) -> None:
    event_metadata: dict[str, str] = {"code": error_code}
    if metadata:
        event_metadata.update(metadata)

    audit_repo.create_event(
        action="auth.callback.failed",
        target_type="oauth_callback",
        target_id=target_state or "missing",
        metadata=event_metadata,
    )


def _nonce_error_detail(exc: PeeringDBNonceValidationError) -> str:
    detail_map = {
        "missing id_token for nonce validation": "missing_id_token",
        "id_token nonce claim missing": "missing_nonce_claim",
        "id_token nonce mismatch": "nonce_mismatch",
        "invalid id_token format": "invalid_id_token_format",
        "invalid id_token payload": "invalid_id_token_payload",
    }
    return detail_map.get(str(exc), "invalid_nonce_token")


def _audit_local_login_failure(
    audit_repo: AuditEventRepository,
    *,
    login_username: str,
    failure_code: str,
    actor_user_id: uuid.UUID | None = None,
) -> None:
    audit_repo.create_event(
        action="auth.local_login.failed",
        target_type="local_login",
        target_id=login_username,
        actor_user_id=actor_user_id,
        metadata={
            "code": failure_code,
            "login_username": login_username,
        },
    )


def _serialize_user_summary(user: AppUser) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "is_admin": user.is_admin,
    }


def _success_response(data: dict[str, Any], *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"data": data})


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            }
        },
    )
