from __future__ import annotations

from dataclasses import replace

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


def test_local_login_success_sets_session(client: TestClient, db_session: Session) -> None:
    user = _create_local_user(
        db_session,
        username="operator-local",
        password="correct horse battery staple",
        asns=(64512,),
    )

    response = client.post(
        "/api/v1/auth/local/login",
        json={"username": " Operator-Local ", "password": "correct horse battery staple"},
    )

    assert response.status_code == 200
    login_body = response.json()["data"]
    assert login_body["auth"]["mode"] == "local"
    assert login_body["auth"]["authorized_asn_count"] == 1
    assert login_body["auth"]["has_eligible_asn"] is True

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
        "/api/v1/auth/local/login",
        json={"username": "missing-user", "password": "anything"},
    )
    assert unknown_user.status_code == 401
    assert unknown_user.json()["error"]["code"] == "local_invalid_credentials"

    wrong_password = client.post(
        "/api/v1/auth/local/login",
        json={"username": "known-user", "password": "wrong password"},
    )
    assert wrong_password.status_code == 401
    assert wrong_password.json()["error"]["code"] == "local_invalid_credentials"

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


def test_local_login_onboarding_context_filters_networks_by_access_assignment(
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
        "/api/v1/auth/local/login",
        json={"username": "restricted-user", "password": "restricted password value"},
    )
    assert login.status_code == 200

    onboarding_response = client.get("/api/v1/onboarding/context")
    assert onboarding_response.status_code == 200
    onboarding_body = onboarding_response.json()["data"]
    assert onboarding_body["zt_networks"] == [
        {
            "id": "1234567890abcdef",
            "name": "Network cdef",
            "description": None,
            "is_active": True,
        }
    ]
    assert onboarding_body["constraints"]["has_network_restrictions"] is True
    assert onboarding_body["constraints"]["restricted_network_ids"] == ["1234567890abcdef"]


def test_local_login_disabled_credential_returns_support_path_error(
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
        "/api/v1/auth/local/login",
        json={"username": "disabled-user", "password": "disabled password value"},
    )

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "local_credential_disabled"
    assert error["details"]["detail_code"] == "contact_support"

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
        "/api/v1/auth/local/login",
        json={"username": "toggle-user", "password": "toggle password value"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "local_auth_disabled"


def test_local_login_without_eligible_asn_keeps_session_and_blocks_submission(
    client: TestClient,
    db_session: Session,
) -> None:
    _seed_network(db_session, "abcdef0123456789")
    _create_local_user(
        db_session,
        username="no-asn-user",
        password="no asn password value",
        asns=(),
    )

    login = client.post(
        "/api/v1/auth/local/login",
        json={"username": "no-asn-user", "password": "no asn password value"},
    )

    assert login.status_code == 200
    login_body = login.json()["data"]
    assert login_body["auth"]["authorized_asn_count"] == 0
    assert login_body["auth"]["has_eligible_asn"] is False

    onboarding = client.get("/api/v1/onboarding/context")
    assert onboarding.status_code == 200
    constraints = onboarding.json()["data"]["constraints"]
    assert constraints["submission_allowed"] is False
    assert constraints["blocked_reason"] == "no_eligible_asn"


def test_auth_logout_clears_authenticated_session(
    client: TestClient,
    db_session: Session,
) -> None:
    _create_local_user(
        db_session,
        username="logout-user",
        password="logout password value",
        asns=(64512,),
    )
    login = client.post(
        "/api/v1/auth/local/login",
        json={"username": "logout-user", "password": "logout password value"},
    )
    assert login.status_code == 200

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert logout.json()["data"]["logged_out"] is True

    me_after_logout = client.get("/api/v1/me")
    assert me_after_logout.status_code == 401
    assert me_after_logout.json()["error"]["code"] == "unauthenticated"


def test_auth_logout_requires_authenticated_session(client: TestClient) -> None:
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


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


def _seed_network(db_session: Session, network_id: str) -> None:
    existing = db_session.get(ZtNetwork, network_id)
    if existing is not None:
        return
    db_session.add(ZtNetwork(id=network_id, name=f"Network {network_id[-4:]}", is_active=True))
    db_session.commit()
