from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AppUser, AuditEvent, OauthStateNonce, UserAsn
from app.integrations.peeringdb import (
    PeeringDBNetwork,
    PeeringDBTokenExchangeError,
    PeeringDBTokenResponse,
    PeeringDBUserProfile,
)
from tests.auth.conftest import StubPeeringDBClient


def test_auth_login_persists_state_and_redirects(client: TestClient, db_session: Session) -> None:
    response = client.get("/auth/login", follow_redirects=False)

    assert response.status_code == 302
    location = response.headers["location"]

    parsed = urlparse(location)
    params = parse_qs(parsed.query)

    assert location.startswith("https://auth.peeringdb.com/oauth2/authorize/?")
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid profile email networks"]
    assert params["code_challenge_method"] == ["S256"]

    state = params["state"][0]
    nonce = params["nonce"][0]

    oauth_row = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one()
    assert oauth_row.nonce == nonce

    login_audit = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.login.started")
        .order_by(AuditEvent.created_at.desc())
    ).scalar_one()
    assert login_audit.target_id == state


def test_auth_callback_success_upserts_user_and_asns(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    login_params = parse_qs(urlparse(login_response.headers["location"]).query)
    state = login_params["state"][0]

    oauth_row = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one()

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=_unsigned_id_token({"nonce": oauth_row.nonce, "sub": "2002"}),
    )
    stub_peeringdb_client.profile_result = PeeringDBUserProfile(
        peeringdb_user_id=2002,
        username="netop",
        full_name="Network Operator",
        email="netop@example.net",
        networks=(
            PeeringDBNetwork(asn=64512, net_id=22, net_name="Net22", perms=15),
            PeeringDBNetwork(asn=64513, net_id=23, net_name="Net23", perms=2),
        ),
    )

    callback_response = client.get(
        f"/auth/callback?code=abc123&state={state}",
        follow_redirects=False,
    )

    assert callback_response.status_code == 302
    assert callback_response.headers["location"] == "http://testserver/onboarding"

    assert len(stub_peeringdb_client.token_calls) == 1
    assert stub_peeringdb_client.token_calls[0]["code_verifier"] == oauth_row.pkce_verifier

    user = db_session.execute(select(AppUser).where(AppUser.peeringdb_user_id == 2002)).scalar_one()
    user_asns = (
        db_session.execute(select(UserAsn).where(UserAsn.user_id == user.id)).scalars().all()
    )
    assert [row.asn for row in user_asns] == [64512]

    consumed_state = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one_or_none()
    assert consumed_state is None

    success_audit = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.callback.succeeded")
        .order_by(AuditEvent.created_at.desc())
    ).scalar_one()
    assert success_audit.target_id == str(user.id)


def test_auth_callback_rejects_invalid_state(client: TestClient, db_session: Session) -> None:
    response = client.get("/auth/callback?code=abc123&state=does-not-exist", follow_redirects=False)

    assert response.status_code == 302
    assert _error_code_from_location(response.headers["location"]) == "invalid_state"

    failure_audit = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.callback.failed")
        .order_by(AuditEvent.created_at.desc())
    ).scalar_one()
    assert failure_audit.event_metadata["code"] == "invalid_state"


def test_auth_callback_handles_token_exchange_failure(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    stub_peeringdb_client.token_result = PeeringDBTokenExchangeError("token endpoint timeout")

    response = client.get(f"/auth/callback?code=abc123&state={state}", follow_redirects=False)

    assert response.status_code == 302
    assert _error_code_from_location(response.headers["location"]) == "upstream_auth_failure"

    consumed_state = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one_or_none()
    assert consumed_state is None


def test_auth_callback_rejects_invalid_nonce(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=_unsigned_id_token({"nonce": "wrong-nonce", "sub": "2002"}),
    )

    response = client.get(f"/auth/callback?code=abc123&state={state}", follow_redirects=False)

    assert response.status_code == 302
    assert _error_code_from_location(response.headers["location"]) == "invalid_nonce"
    assert _error_detail_from_location(response.headers["location"]) == "nonce_mismatch"


def test_auth_callback_missing_id_token_returns_nonce_detail(
    client: TestClient,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=None,
    )

    callback_response = client.get(
        f"/auth/callback?code=abc123&state={state}",
        follow_redirects=False,
    )
    error_location = callback_response.headers["location"]

    assert callback_response.status_code == 302
    assert _error_code_from_location(error_location) == "invalid_nonce"
    assert _error_detail_from_location(error_location) == "missing_id_token"

    error_response = client.get(error_location)
    body = error_response.json()
    assert body["code"] == "invalid_nonce"
    assert body["detail"] == "missing_id_token"
    assert body["message"] == "OIDC nonce validation failed for the returned identity token."


def test_auth_callback_replay_state_is_rejected(
    client: TestClient,
    stub_peeringdb_client: StubPeeringDBClient,
    db_session: Session,
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    oauth_row = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one()
    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=_unsigned_id_token({"nonce": oauth_row.nonce, "sub": "3003"}),
    )
    stub_peeringdb_client.profile_result = PeeringDBUserProfile(
        peeringdb_user_id=3003,
        username="operator-3",
        full_name="Operator Three",
        email="op3@example.net",
        networks=(PeeringDBNetwork(asn=64550, net_id=50, net_name="Net50", perms=15),),
    )

    first = client.get(f"/auth/callback?code=abc123&state={state}", follow_redirects=False)
    second = client.get(f"/auth/callback?code=abc123&state={state}", follow_redirects=False)

    assert first.status_code == 302
    assert second.status_code == 302
    assert _error_code_from_location(second.headers["location"]) == "invalid_state"


def _error_code_from_location(location: str) -> str | None:
    params = parse_qs(urlparse(location).query)
    values = params.get("code")
    if not values:
        return None
    return values[0]


def _error_detail_from_location(location: str) -> str | None:
    params = parse_qs(urlparse(location).query)
    values = params.get("detail")
    if not values:
        return None
    return values[0]


def _unsigned_id_token(payload: dict[str, str]) -> str:
    header_segment = _b64url_json({"alg": "none", "typ": "JWT"})
    payload_segment = _b64url_json(payload)
    return f"{header_segment}.{payload_segment}."


def _b64url_json(value: dict[str, str]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
