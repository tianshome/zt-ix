"""PeeringDB OAuth login/callback/logout routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.datastructures import URL
from starlette.responses import RedirectResponse, Response

from app.auth import (
    generate_nonce,
    generate_pkce_verifier,
    generate_state,
    pkce_code_challenge,
)
from app.config import AppSettings
from app.dependencies import get_app_settings, get_db_session, get_peeringdb_client
from app.integrations.peeringdb import (
    PeeringDBClientError,
    PeeringDBClientProtocol,
    PeeringDBNonceValidationError,
    validate_id_token_nonce,
)
from app.repositories.audit_events import AuditEventRepository
from app.repositories.oauth_state_nonces import (
    OauthStateConsumeStatus,
    OauthStateNonceRepository,
)
from app.repositories.user_asns import UserAsnRecord, UserAsnRepository
from app.repositories.users import UserRepository

router = APIRouter(prefix="/auth", tags=["auth"])
SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]
DbSessionDep = Annotated[Session, Depends(get_db_session)]
PeeringDBClientDep = Annotated[PeeringDBClientProtocol, Depends(get_peeringdb_client)]


@router.get("/login")
async def auth_login(
    request: Request,
    settings: SettingsDep,
    db_session: DbSessionDep,
) -> Response:
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
    return RedirectResponse(authorization_url, status_code=302)


@router.get("/callback")
async def auth_callback(
    request: Request,
    peeringdb_client: PeeringDBClientDep,
    db_session: DbSessionDep,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    audit_repo = AuditEventRepository(db_session)

    if error:
        _audit_callback_failure(
            audit_repo,
            error_code="oauth_error",
            target_state=state,
            metadata={"oauth_error": error},
        )
        db_session.commit()
        return _error_redirect(request, "oauth_error")

    if not code or not state:
        _audit_callback_failure(audit_repo, error_code="missing_code_or_state", target_state=state)
        db_session.commit()
        return _error_redirect(request, "missing_code_or_state")

    oauth_repo = OauthStateNonceRepository(db_session)
    consume_result = oauth_repo.consume_state(state=state)

    if consume_result.status is OauthStateConsumeStatus.MISSING:
        _audit_callback_failure(audit_repo, error_code="invalid_state", target_state=state)
        db_session.commit()
        return _error_redirect(request, "invalid_state")

    if consume_result.status is OauthStateConsumeStatus.EXPIRED:
        _audit_callback_failure(audit_repo, error_code="expired_state", target_state=state)
        db_session.commit()
        return _error_redirect(request, "expired_state")

    state_row = consume_result.row
    if state_row is None:
        _audit_callback_failure(audit_repo, error_code="invalid_state", target_state=state)
        db_session.commit()
        return _error_redirect(request, "invalid_state")

    try:
        token_response = await peeringdb_client.exchange_code_for_tokens(
            code=code,
            code_verifier=state_row.pkce_verifier,
            redirect_uri=state_row.redirect_uri,
        )
        validate_id_token_nonce(id_token=token_response.id_token, expected_nonce=state_row.nonce)
        profile = await peeringdb_client.fetch_profile(access_token=token_response.access_token)
    except PeeringDBNonceValidationError as exc:
        _audit_callback_failure(
            audit_repo,
            error_code="invalid_nonce",
            target_state=state,
            metadata={"detail": str(exc)},
        )
        db_session.commit()
        return _error_redirect(request, "invalid_nonce")
    except PeeringDBClientError as exc:
        _audit_callback_failure(
            audit_repo,
            error_code="upstream_auth_failure",
            target_state=state,
            metadata={"detail": str(exc)},
        )
        db_session.commit()
        return _error_redirect(request, "upstream_auth_failure")

    user_repo = UserRepository(db_session)
    user_asn_repo = UserAsnRepository(db_session)

    user = user_repo.upsert_peeringdb_user(
        peeringdb_user_id=profile.peeringdb_user_id,
        username=profile.username,
        full_name=profile.full_name,
        email=profile.email,
        is_admin=False,
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
        return _error_redirect(request, "no_eligible_asn")

    db_session.commit()
    return RedirectResponse(str(request.url_for("onboarding_page")), status_code=302)


@router.get("/logout")
async def auth_logout(
    request: Request,
    db_session: DbSessionDep,
) -> Response:
    actor_user_id = _session_user_id(request)
    request.session.clear()

    AuditEventRepository(db_session).create_event(
        action="auth.logout",
        target_type="auth_session",
        target_id=str(actor_user_id) if actor_user_id else "anonymous",
        actor_user_id=actor_user_id,
    )
    db_session.commit()

    return RedirectResponse(str(request.url_for("root")), status_code=302)


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


def _error_redirect(request: Request, code: str) -> RedirectResponse:
    error_url = URL(str(request.url_for("error_page"))).include_query_params(code=code)
    return RedirectResponse(str(error_url), status_code=302)
