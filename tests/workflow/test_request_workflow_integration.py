from __future__ import annotations

import base64
import json
import uuid
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.enums import RequestStatus
from app.db.models import AppUser, AuditEvent, JoinRequest, OauthStateNonce, ZtNetwork
from app.integrations.peeringdb import (
    PeeringDBNetwork,
    PeeringDBTokenResponse,
    PeeringDBUserProfile,
)
from tests.workflow.conftest import StubPeeringDBClient


def test_create_request_enforces_ownership_and_duplicate_conflict(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1201,
        username="operator-1201",
        asns=(64512,),
    )

    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "abcdef0123456789", "node_id": "abcde12345"},
    )
    assert create_response.status_code == 201
    created_request = create_response.json()["data"]["request"]
    assert created_request["status"] == "pending"

    duplicate_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "abcdef0123456789"},
    )
    duplicate_body = duplicate_response.json()["error"]
    assert duplicate_response.status_code == 409
    assert duplicate_body["code"] == "duplicate_active_request"
    assert duplicate_body["details"]["existing_request_id"] == created_request["id"]
    assert duplicate_body["details"]["existing_request_url"] == f"/requests/{created_request['id']}"

    unauthorized_response = client.post(
        "/api/v1/requests",
        json={"asn": 64599, "zt_network_id": "abcdef0123456789"},
    )
    unauthorized_body = unauthorized_response.json()["error"]
    assert unauthorized_response.status_code == 403
    assert unauthorized_body["code"] == "asn_not_authorized"

    created_audits = (
        db_session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "request.created")
            .order_by(AuditEvent.created_at.asc())
        )
        .scalars()
        .all()
    )
    assert len(created_audits) == 1
    assert created_audits[0].target_id == created_request["id"]


def test_operator_dashboard_and_detail_are_user_scoped(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1301,
        username="operator-1301",
        asns=(64520,),
    )
    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64520, "zt_network_id": "abcdef0123456789"},
    )
    request_id = create_response.json()["data"]["request"]["id"]

    dashboard_response = client.get("/dashboard")
    assert dashboard_response.status_code == 200
    dashboard_body = dashboard_response.json()
    assert dashboard_body["request_count"] == 1
    assert dashboard_body["requests"][0]["id"] == request_id

    own_detail_response = client.get(f"/requests/{request_id}")
    assert own_detail_response.status_code == 200
    assert own_detail_response.json()["request"]["id"] == request_id

    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1302,
        username="operator-1302",
        asns=(64521,),
    )
    cross_user_page_response = client.get(f"/requests/{request_id}")
    assert cross_user_page_response.status_code == 404

    cross_user_api_response = client.get(f"/api/v1/requests/{request_id}")
    assert cross_user_api_response.status_code == 404
    assert cross_user_api_response.json()["error"]["code"] == "request_not_found"


def test_admin_queue_filters_and_approve_reject_transitions(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1401,
        username="operator-1401",
        asns=(64600, 64601),
    )

    first_request_response = client.post(
        "/api/v1/requests",
        json={"asn": 64600, "zt_network_id": "abcdef0123456789"},
    )
    first_request_id = first_request_response.json()["data"]["request"]["id"]

    second_request_response = client.post(
        "/api/v1/requests",
        json={"asn": 64601, "zt_network_id": "abcdef0123456789"},
    )
    second_request_id = second_request_response.json()["data"]["request"]["id"]

    db_session.add(
        AppUser(
            peeringdb_user_id=9001,
            username="admin-user",
            full_name="Admin User",
            is_admin=True,
        )
    )
    db_session.commit()

    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=9001,
        username="admin-user",
        asns=(64550,),
    )

    pending_queue_response = client.get("/admin/requests?status=pending")
    assert pending_queue_response.status_code == 200
    pending_ids = {row["id"] for row in pending_queue_response.json()["requests"]}
    assert first_request_id in pending_ids
    assert second_request_id in pending_ids

    approve_response = client.post(f"/api/v1/admin/requests/{first_request_id}/approve")
    assert approve_response.status_code == 200
    assert approve_response.json()["data"]["request"]["status"] == "approved"

    invalid_reapprove = client.post(f"/api/v1/admin/requests/{first_request_id}/approve")
    assert invalid_reapprove.status_code == 409
    assert invalid_reapprove.json()["error"]["code"] == "invalid_status_transition"

    reject_without_reason = client.post(
        f"/api/v1/admin/requests/{second_request_id}/reject",
        json={},
    )
    assert reject_without_reason.status_code == 400
    assert reject_without_reason.json()["error"]["code"] == "reject_reason_required"

    reject_with_reason = client.post(
        f"/api/v1/admin/requests/{second_request_id}/reject",
        json={"reject_reason": "Policy mismatch"},
    )
    assert reject_with_reason.status_code == 200
    assert reject_with_reason.json()["data"]["request"]["status"] == "rejected"

    approved_queue_response = client.get("/admin/requests?status=approved")
    assert approved_queue_response.status_code == 200
    approved_ids = {row["id"] for row in approved_queue_response.json()["requests"]}
    assert first_request_id in approved_ids
    assert second_request_id not in approved_ids

    transition_audits = (
        db_session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "request.status.changed")
            .order_by(AuditEvent.created_at.asc())
        )
        .scalars()
        .all()
    )
    assert len(transition_audits) >= 2


def test_admin_retry_endpoint_requires_failed_status(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1501,
        username="operator-1501",
        asns=(64650,),
    )
    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64650, "zt_network_id": "abcdef0123456789"},
    )
    request_id = create_response.json()["data"]["request"]["id"]

    db_session.add(
        AppUser(
            peeringdb_user_id=9002,
            username="admin-user-2",
            full_name="Admin User Two",
            is_admin=True,
        )
    )
    db_session.commit()
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=9002,
        username="admin-user-2",
        asns=(64551,),
    )

    non_failed_retry = client.post(f"/api/v1/admin/requests/{request_id}/retry")
    assert non_failed_retry.status_code == 409
    assert non_failed_retry.json()["error"]["code"] == "invalid_status_transition"

    request_row = db_session.execute(
        select(JoinRequest).where(JoinRequest.id == uuid.UUID(request_id))
    ).scalar_one()
    request_row.status = RequestStatus.FAILED
    request_row.last_error = "prior provider error"
    db_session.commit()

    valid_retry = client.post(f"/api/v1/admin/requests/{request_id}/retry")
    assert valid_retry.status_code == 200
    assert valid_retry.json()["data"]["request"]["status"] == "approved"


def test_non_admin_is_rejected_from_admin_routes(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1601,
        username="operator-1601",
        asns=(64700,),
    )

    admin_page_response = client.get("/admin/requests")
    assert admin_page_response.status_code == 403

    admin_api_response = client.post(f"/api/v1/admin/requests/{uuid.uuid4()}/approve")
    assert admin_api_response.status_code == 403
    assert admin_api_response.json()["error"]["code"] == "forbidden"


def _seed_network(db_session: Session) -> None:
    existing = db_session.get(ZtNetwork, "abcdef0123456789")
    if existing is not None:
        return
    db_session.add(ZtNetwork(id="abcdef0123456789", name="ZT IX Fabric", is_active=True))
    db_session.commit()


def _authenticate_session(
    *,
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
    peeringdb_user_id: int,
    username: str,
    asns: tuple[int, ...],
) -> None:
    login_response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]
    oauth_row = db_session.execute(
        select(OauthStateNonce).where(OauthStateNonce.state == state)
    ).scalar_one()

    stub_peeringdb_client.token_result = PeeringDBTokenResponse(
        access_token=f"token-{peeringdb_user_id}",
        id_token=_unsigned_id_token({"nonce": oauth_row.nonce, "sub": str(peeringdb_user_id)}),
    )
    stub_peeringdb_client.profile_result = PeeringDBUserProfile(
        peeringdb_user_id=peeringdb_user_id,
        username=username,
        full_name=f"User {peeringdb_user_id}",
        email=f"{username}@example.net",
        networks=tuple(
            PeeringDBNetwork(asn=asn, net_id=index, net_name=f"Net{asn}", perms=15)
            for index, asn in enumerate(asns, start=1)
        ),
    )

    callback_response = client.get(
        f"/auth/callback?code=code-{peeringdb_user_id}&state={state}",
        follow_redirects=False,
    )
    assert callback_response.status_code == 302
    assert callback_response.headers["location"] == "http://testserver/onboarding"


def _unsigned_id_token(payload: dict[str, str]) -> str:
    header_segment = _b64url_json({"alg": "none", "typ": "JWT"})
    payload_segment = _b64url_json(payload)
    return f"{header_segment}.{payload_segment}."


def _b64url_json(value: dict[str, str]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
