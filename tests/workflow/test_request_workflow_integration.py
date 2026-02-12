from __future__ import annotations

import base64
import json
import uuid
from dataclasses import replace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AppSettings
from app.db.enums import RequestStatus
from app.db.models import (
    AppUser,
    AuditEvent,
    JoinRequest,
    OauthStateNonce,
    UserNetworkAccess,
    ZtIpv6Assignment,
    ZtMembership,
    ZtNetwork,
)
from app.integrations.peeringdb import (
    PeeringDBNetwork,
    PeeringDBTokenResponse,
    PeeringDBUserProfile,
)
from tests.workflow.conftest import StubPeeringDBClient


def test_onboarding_context_returns_eligible_asns_and_network_constraints(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session, network_id="abcdef0123456789")
    _seed_network(db_session, network_id="1234567890abcdef")

    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1101,
        username="operator-1101",
        asns=(64511,),
    )
    user = db_session.execute(select(AppUser).where(AppUser.peeringdb_user_id == 1101)).scalar_one()
    db_session.add(
        UserNetworkAccess(
            user_id=user.id,
            zt_network_id="1234567890abcdef",
            source="local",
        )
    )
    db_session.commit()

    response = client.get("/api/v1/onboarding/context")
    assert response.status_code == 200
    body = response.json()["data"]
    assert body["eligible_asns"][0]["asn"] == 64511
    assert body["zt_networks"] == [
        {
            "id": "1234567890abcdef",
            "name": "ZT IX Fabric cdef",
            "description": None,
            "is_active": True,
        }
    ]
    assert body["constraints"]["has_network_restrictions"] is True
    assert body["constraints"]["restricted_network_ids"] == ["1234567890abcdef"]
    assert body["constraints"]["submission_allowed"] is True
    assert body["constraints"]["blocked_reason"] is None


def test_create_request_allows_distinct_node_ids_and_enforces_duplicate_conflict(
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

    second_create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "abcdef0123456789", "node_id": "ffffe12345"},
    )
    assert second_create_response.status_code == 201
    second_created_request = second_create_response.json()["data"]["request"]
    assert second_created_request["status"] == "pending"

    duplicate_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "abcdef0123456789", "node_id": "abcde12345"},
    )
    duplicate_body = duplicate_response.json()["error"]
    assert duplicate_response.status_code == 409
    assert duplicate_body["code"] == "duplicate_active_request"
    assert duplicate_body["details"]["node_id"] == "abcde12345"
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
    assert len(created_audits) == 2
    assert {audit.target_id for audit in created_audits} == {
        created_request["id"],
        second_created_request["id"],
    }


def test_operator_request_api_is_user_scoped(
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

    own_list_response = client.get("/api/v1/requests")
    assert own_list_response.status_code == 200
    own_requests = own_list_response.json()["data"]["requests"]
    assert len(own_requests) == 1
    assert own_requests[0]["id"] == request_id

    own_detail_response = client.get(f"/api/v1/requests/{request_id}")
    assert own_detail_response.status_code == 200
    assert own_detail_response.json()["data"]["request"]["id"] == request_id

    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1302,
        username="operator-1302",
        asns=(64521,),
    )
    cross_user_detail_response = client.get(f"/api/v1/requests/{request_id}")
    assert cross_user_detail_response.status_code == 404
    assert cross_user_detail_response.json()["error"]["code"] == "request_not_found"


def test_request_api_detail_includes_membership_when_present(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1351,
        username="operator-1351",
        asns=(64531,),
    )

    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64531, "zt_network_id": "abcdef0123456789", "node_id": "abcde12345"},
    )
    request_id = create_response.json()["data"]["request"]["id"]
    request_uuid = uuid.UUID(request_id)

    request_row = db_session.execute(
        select(JoinRequest).where(JoinRequest.id == request_uuid)
    ).scalar_one()
    request_row.status = RequestStatus.ACTIVE
    db_session.add(
        ZtMembership(
            join_request_id=request_row.id,
            zt_network_id=request_row.zt_network_id,
            node_id="abcde12345",
            member_id="member-xyz",
            is_authorized=True,
            assigned_ips=["10.0.0.5/32"],
        )
    )
    db_session.commit()

    detail_response = client.get(f"/api/v1/requests/{request_id}")
    assert detail_response.status_code == 200
    membership = detail_response.json()["data"]["request"]["membership"]
    assert membership is not None
    assert membership["member_id"] == "member-xyz"
    assert membership["assigned_ips"] == ["10.0.0.5/32"]


def test_request_apis_expose_assigned_ipv6_from_sql_assignment(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1361,
        username="operator-1361",
        asns=(64532,),
    )

    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64532, "zt_network_id": "abcdef0123456789", "node_id": "abcde12345"},
    )
    request_id = create_response.json()["data"]["request"]["id"]
    request_uuid = uuid.UUID(request_id)

    request_row = db_session.execute(
        select(JoinRequest).where(JoinRequest.id == request_uuid)
    ).scalar_one()
    db_session.add(
        ZtIpv6Assignment(
            join_request_id=request_row.id,
            zt_network_id=request_row.zt_network_id,
            asn=request_row.asn,
            sequence=1,
            assigned_ip="2001:db8:100:0:6:11a0:0:1/128",
        )
    )
    db_session.commit()

    detail_response = client.get(f"/api/v1/requests/{request_id}")
    assert detail_response.status_code == 200
    detail_request = detail_response.json()["data"]["request"]
    assert detail_request["assigned_ipv6"] == "2001:db8:100:0:6:11a0:0:1/128"
    assert detail_request["ipv6_assignment"]["assigned_ip"] == "2001:db8:100:0:6:11a0:0:1/128"

    list_response = client.get("/api/v1/requests")
    assert list_response.status_code == 200
    listed_request = next(
        row for row in list_response.json()["data"]["requests"] if row["id"] == request_id
    )
    assert listed_request["assigned_ipv6"] == "2001:db8:100:0:6:11a0:0:1/128"

    db_session.add(
        AppUser(
            peeringdb_user_id=9061,
            username="admin-ipv6",
            full_name="Admin IPv6",
            is_admin=True,
        )
    )
    db_session.commit()
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=9061,
        username="admin-ipv6",
        asns=(64533,),
    )

    admin_list_response = client.get("/api/v1/admin/requests")
    assert admin_list_response.status_code == 200
    admin_row = next(
        row for row in admin_list_response.json()["data"]["requests"] if row["id"] == request_id
    )
    assert admin_row["assigned_ipv6"] == "2001:db8:100:0:6:11a0:0:1/128"

    admin_detail_response = client.get(f"/api/v1/admin/requests/{request_id}")
    assert admin_detail_response.status_code == 200
    assert (
        admin_detail_response.json()["data"]["request"]["assigned_ipv6"]
        == "2001:db8:100:0:6:11a0:0:1/128"
    )


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

    pending_queue_response = client.get("/api/v1/admin/requests?status=pending")
    assert pending_queue_response.status_code == 200
    pending_ids = {row["id"] for row in pending_queue_response.json()["data"]["requests"]}
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

    approved_queue_response = client.get("/api/v1/admin/requests?status=approved")
    assert approved_queue_response.status_code == 200
    approved_ids = {row["id"] for row in approved_queue_response.json()["data"]["requests"]}
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


def test_admin_request_detail_includes_audit_context(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1451,
        username="operator-1451",
        asns=(64551,),
    )
    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64551, "zt_network_id": "abcdef0123456789"},
    )
    request_id = create_response.json()["data"]["request"]["id"]

    db_session.add(
        AppUser(
            peeringdb_user_id=9051,
            username="admin-detail",
            full_name="Admin Detail",
            is_admin=True,
        )
    )
    db_session.commit()
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=9051,
        username="admin-detail",
        asns=(64552,),
    )

    detail_response = client.get(f"/api/v1/admin/requests/{request_id}")
    assert detail_response.status_code == 200
    detail_body = detail_response.json()["data"]
    assert detail_body["request"]["id"] == request_id
    assert detail_body["audit_events"]


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

    admin_list_response = client.get("/api/v1/admin/requests")
    assert admin_list_response.status_code == 403
    assert admin_list_response.json()["error"]["code"] == "forbidden"

    admin_api_response = client.post(f"/api/v1/admin/requests/{uuid.uuid4()}/approve")
    assert admin_api_response.status_code == 403
    assert admin_api_response.json()["error"]["code"] == "forbidden"


def test_create_request_enforces_associated_network_access(
    client: TestClient,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session, network_id="abcdef0123456789")
    _seed_network(db_session, network_id="1234567890abcdef")

    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1701,
        username="operator-1701",
        asns=(64512,),
    )
    user = db_session.execute(select(AppUser).where(AppUser.peeringdb_user_id == 1701)).scalar_one()
    db_session.add(
        UserNetworkAccess(
            user_id=user.id,
            zt_network_id="1234567890abcdef",
            source="local",
        )
    )
    db_session.commit()

    blocked_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "abcdef0123456789"},
    )
    assert blocked_response.status_code == 403
    blocked_body = blocked_response.json()["error"]
    assert blocked_body["code"] == "network_not_authorized"
    assert blocked_body["details"]["allowed_network_ids"] == ["1234567890abcdef"]

    allowed_response = client.post(
        "/api/v1/requests",
        json={"asn": 64512, "zt_network_id": "1234567890abcdef"},
    )
    assert allowed_response.status_code == 201


def test_policy_auto_mode_auto_approves_and_emits_policy_audit(
    client: TestClient,
    test_app: FastAPI,
    workflow_settings: AppSettings,
    db_session: Session,
    stub_peeringdb_client: StubPeeringDBClient,
) -> None:
    _seed_network(db_session)
    test_app.state.settings = replace(workflow_settings, workflow_approval_mode="policy_auto")
    _authenticate_session(
        client=client,
        db_session=db_session,
        stub_peeringdb_client=stub_peeringdb_client,
        peeringdb_user_id=1801,
        username="operator-1801",
        asns=(64801,),
    )

    create_response = client.post(
        "/api/v1/requests",
        json={"asn": 64801, "zt_network_id": "abcdef0123456789"},
    )
    assert create_response.status_code == 201
    created_request = create_response.json()["data"]["request"]
    assert created_request["status"] == "approved"

    transition_audit = (
        db_session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "request.status.changed")
            .order_by(AuditEvent.created_at.desc())
        )
        .scalars()
        .first()
    )
    assert transition_audit is not None
    assert transition_audit.actor_user_id is None
    assert transition_audit.event_metadata["approval_mode"] == "policy_auto"
    assert transition_audit.event_metadata["decision_source"] == "policy_auto"
    assert transition_audit.event_metadata["auto_approved"] is True


def _seed_network(db_session: Session, *, network_id: str = "abcdef0123456789") -> None:
    existing = db_session.get(ZtNetwork, network_id)
    if existing is not None:
        return
    db_session.add(ZtNetwork(id=network_id, name=f"ZT IX Fabric {network_id[-4:]}", is_active=True))
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
    start_response = client.post("/api/v1/auth/peeringdb/start")
    start_body = start_response.json()["data"]
    state = start_body["state"]
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

    callback_response = client.post(
        "/api/v1/auth/peeringdb/callback",
        json={"code": f"code-{peeringdb_user_id}", "state": state},
    )
    assert callback_response.status_code == 200


def _unsigned_id_token(payload: dict[str, str]) -> str:
    header_segment = _b64url_json({"alg": "none", "typ": "JWT"})
    payload_segment = _b64url_json(payload)
    return f"{header_segment}.{payload_segment}."


def _b64url_json(value: dict[str, str]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
