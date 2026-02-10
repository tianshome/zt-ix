from __future__ import annotations

from dataclasses import replace
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import hash_password, normalize_login_username
from app.config import AppSettings
from app.db.models import (
    AppUser,
    AuditEvent,
    LocalCredential,
    UserAsn,
    UserNetworkAccess,
    ZtNetwork,
)


def test_local_login_success_sets_session_and_redirects(
    client: TestClient,
    db_session: Session,
) -> None:
    user = _create_local_user(
        db_session,
        username="operator-local",
        password="correct horse battery staple",
        asns=(64512,),
    )

    response = client.post(
        "/auth/local/login",
        json={"username": " Operator-Local ", "password": "correct horse battery staple"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "http://testserver/onboarding"

    credential_row = db_session.execute(
        select(LocalCredential).where(LocalCredential.user_id == user.id)
    ).scalar_one()
    assert credential_row.last_login_at is not None

    me_response = client.get("/api/v1/me")
    assert me_response.status_code == 200
    body = me_response.json()["data"]
    assert body["user"]["id"] == str(user.id)
    assert body["user"]["username"] == "operator-local"

    success_audit = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.local_login.succeeded")
        .order_by(AuditEvent.created_at.desc())
    ).scalar_one()
    assert success_audit.actor_user_id == user.id


def test_local_login_unknown_user_and_wrong_password_share_error_code(
    client: TestClient,
    db_session: Session,
) -> None:
    _create_local_user(
        db_session,
        username="known-user",
        password="known password value",
        asns=(64512,),
    )

    unknown_user = client.post(
        "/auth/local/login",
        json={"username": "missing-user", "password": "anything"},
        follow_redirects=False,
    )
    assert unknown_user.status_code == 302
    assert _error_code(unknown_user.headers["location"]) == "local_invalid_credentials"

    wrong_password = client.post(
        "/auth/local/login",
        json={"username": "known-user", "password": "wrong password"},
        follow_redirects=False,
    )
    assert wrong_password.status_code == 302
    assert _error_code(wrong_password.headers["location"]) == "local_invalid_credentials"

    failed_audits = (
        db_session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "auth.local_login.failed")
            .order_by(AuditEvent.created_at.asc())
        )
        .scalars()
        .all()
    )
    assert len(failed_audits) >= 2
    assert failed_audits[-2].event_metadata["code"] == "invalid_credentials"
    assert failed_audits[-1].event_metadata["code"] == "invalid_credentials"


def test_local_login_onboarding_filters_networks_by_access_assignment(
    client: TestClient,
    db_session: Session,
) -> None:
    _seed_network(db_session, "abcdef0123456789")
    _seed_network(db_session, "1234567890abcdef")
    user = _create_local_user(
        db_session,
        username="restricted-user",
        password="restricted password value",
        asns=(64512,),
    )
    db_session.add(
        UserNetworkAccess(
            user_id=user.id,
            zt_network_id="1234567890abcdef",
            source="local",
        )
    )
    db_session.commit()

    login = client.post(
        "/auth/local/login",
        json={"username": "restricted-user", "password": "restricted password value"},
        follow_redirects=False,
    )
    assert login.status_code == 302
    assert login.headers["location"] == "http://testserver/onboarding"

    onboarding_response = client.get("/onboarding")
    assert onboarding_response.status_code == 200
    onboarding_body = onboarding_response.json()
    assert onboarding_body["zt_networks"] == [
        {
            "id": "1234567890abcdef",
            "name": "Network cdef",
            "description": None,
        }
    ]


def test_local_login_disabled_credential_redirects_support_path(
    client: TestClient,
    db_session: Session,
) -> None:
    _create_local_user(
        db_session,
        username="disabled-user",
        password="disabled password value",
        asns=(64512,),
        is_enabled=False,
    )

    response = client.post(
        "/auth/local/login",
        json={"username": "disabled-user", "password": "disabled password value"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert _error_code(response.headers["location"]) == "local_credential_disabled"
    assert _error_detail(response.headers["location"]) == "contact_support"

    failed_audit = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.local_login.failed")
        .order_by(AuditEvent.created_at.desc())
    ).scalar_one()
    assert failed_audit.event_metadata["code"] == "credential_disabled"


def test_local_login_respects_local_auth_toggle(
    client: TestClient,
    test_app: FastAPI,
    auth_settings: AppSettings,
    db_session: Session,
) -> None:
    _create_local_user(
        db_session,
        username="toggle-user",
        password="toggle password value",
        asns=(64512,),
    )
    test_app.state.settings = replace(auth_settings, local_auth_enabled=False)

    response = client.post(
        "/auth/local/login",
        json={"username": "toggle-user", "password": "toggle password value"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert _error_code(response.headers["location"]) == "local_auth_disabled"


def test_local_login_without_eligible_asn_redirects_error(
    client: TestClient,
    db_session: Session,
) -> None:
    _create_local_user(
        db_session,
        username="no-asn-user",
        password="no asn password value",
        asns=(),
    )

    response = client.post(
        "/auth/local/login",
        json={"username": "no-asn-user", "password": "no asn password value"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert _error_code(response.headers["location"]) == "no_eligible_asn"


def _create_local_user(
    db_session: Session,
    *,
    username: str,
    password: str,
    asns: tuple[int, ...],
    is_enabled: bool = True,
) -> AppUser:
    normalized_username = normalize_login_username(username)
    user = AppUser(
        peeringdb_user_id=None,
        username=normalized_username,
        full_name=normalized_username,
        email=f"{normalized_username}@example.net",
    )
    db_session.add(user)
    db_session.flush()

    db_session.add(
        LocalCredential(
            user_id=user.id,
            login_username=normalized_username,
            password_hash=hash_password(password=password, min_length=12, iterations=100_000),
            is_enabled=is_enabled,
        )
    )
    for asn in asns:
        db_session.add(UserAsn(user_id=user.id, asn=asn, source="local"))

    db_session.commit()
    return user


def _error_code(location: str) -> str | None:
    values = parse_qs(urlparse(location).query).get("code")
    if not values:
        return None
    return values[0]


def _error_detail(location: str) -> str | None:
    values = parse_qs(urlparse(location).query).get("detail")
    if not values:
        return None
    return values[0]


def _seed_network(db_session: Session, network_id: str) -> None:
    existing = db_session.get(ZtNetwork, network_id)
    if existing is not None:
        return
    db_session.add(ZtNetwork(id=network_id, name=f"Network {network_id[-4:]}", is_active=True))
    db_session.commit()
