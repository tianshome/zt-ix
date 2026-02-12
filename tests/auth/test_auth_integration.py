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


def test_auth_start_persists_state_and_returns_authorization_url(
    client: TestClient,
    db_session: Session,
) -> None:
    response = client.post("/api/v1/auth/peeringdb/start")

    assert response.status_code == 200
    body = response.json()["data"]
    location = body["authorization_url"]

    parsed = urlparse(location)
    params = parse_qs(parsed.query)

    assert location.startswith("https://auth.peeringdb.com/oauth2/authorize/?")
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid profile email networks"]
    assert params["code_challenge_method"] == ["S256"]

    state = body["state"]
    nonce = params["nonce"][0]
    assert params["state"] == [state]

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
    start_response = client.post("/api/v1/auth/peeringdb/start")
    state = start_response.json()["data"]["state"]

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

    callback_response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )

    assert callback_response.status_code == 200
    callback_body = callback_response.json()["data"]
    assert callback_body["auth"]["mode"] == "peeringdb"
    assert callback_body["auth"]["authorized_asn_count"] == 1
    assert callback_body["auth"]["has_eligible_asn"] is True

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
    response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": "does-not-exist"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_state"

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
    start_response = client.post("/api/v1/auth/peeringdb/start")
    state = start_response.json()["data"]["state"]

    stub_peeringdb_client.token_result = PeeringDBTokenExchangeError("token endpoint timeout")

    response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "upstream_auth_failure"

    consumed_state = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one_or_none()
    assert consumed_state is None


def test_auth_callback_rejects_invalid_nonce(
    client: TestClient,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    start_response = client.post("/api/v1/auth/peeringdb/start")
    state = start_response.json()["data"]["state"]

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=_unsigned_id_token({"nonce": "wrong-nonce", "sub": "2002"}),
    )

    response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_nonce"
    assert response.json()["error"]["details"]["detail_code"] == "nonce_mismatch"


def test_auth_callback_missing_id_token_returns_nonce_detail(
    client: TestClient,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    start_response = client.post("/api/v1/auth/peeringdb/start")
    state = start_response.json()["data"]["state"]

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token="token-success",
        id_token=None,
    )

    callback_response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )

    assert callback_response.status_code == 400
    assert callback_response.json()["error"]["code"] == "invalid_nonce"
    assert callback_response.json()["error"]["details"]["detail_code"] == "missing_id_token"


def test_auth_callback_replay_state_is_rejected(
    client: TestClient,
    stub_peeringdb_client: StubPeeringDBClient,
    db_session: Session,
) -> None:
    start_response = client.post("/api/v1/auth/peeringdb/start")
    state = start_response.json()["data"]["state"]

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

    first = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )
    second = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": "abc123", "state": state},
    )

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"]["code"] == "invalid_state"


def _unsigned_id_token(payload: dict[str, str]) -> str:
    header_segment = _b64url_json({"alg": "none", "typ": "JWT"})
    payload_segment = _b64url_json(payload)
    return f"{header_segment}.{payload_segment}."


def _b64url_json(value: dict[str, str]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
