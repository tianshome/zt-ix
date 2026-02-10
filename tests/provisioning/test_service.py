from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.enums import RequestStatus
from app.db.models import AppUser, AuditEvent, JoinRequest, ZtMembership, ZtNetwork
from app.provisioning.providers.base import ProviderAuthError, ProvisionResult
from app.provisioning.route_servers import RouteServerSyncError, RouteServerSyncResult
from app.provisioning.service import (
    process_join_request_provisioning_with_provider,
)
from app.repositories.join_requests import JoinRequestRepository


@dataclass(slots=True)
class StubProvider:
    provider_name: str = "stub_provider"
    network_exists: bool = True
    authorize_result: ProvisionResult = field(
        default_factory=lambda: ProvisionResult(
            member_id="member-1",
            is_authorized=True,
            assigned_ips=["10.0.0.1/32"],
            provider_name="stub_provider",
        )
    )
    authorize_error: Exception | None = None
    validate_calls: list[str] = field(default_factory=list)
    authorize_calls: list[tuple[str, str, int, uuid.UUID]] = field(default_factory=list)

    def validate_network(self, zt_network_id: str) -> bool:
        self.validate_calls.append(zt_network_id)
        return self.network_exists

    def authorize_member(
        self,
        *,
        zt_network_id: str,
        node_id: str,
        asn: int,
        request_id: uuid.UUID,
    ) -> ProvisionResult:
        self.authorize_calls.append((zt_network_id, node_id, asn, request_id))
        if self.authorize_error is not None:
            raise self.authorize_error
        return self.authorize_result


@dataclass(slots=True)
class StubRouteServerSyncService:
    sync_error: Exception | None = None
    sync_results: list[RouteServerSyncResult] = field(
        default_factory=lambda: [
            RouteServerSyncResult(
                host="rs1.example.net",
                remote_path="/etc/bird/ztix-peers.d/ztix_as64512_req_deadbeef.conf",
                config_sha256="abc123",
            )
        ]
    )
    sync_calls: list[tuple[uuid.UUID, int, str, str, list[str]]] = field(default_factory=list)

    def sync_desired_config(
        self,
        *,
        request_id: uuid.UUID,
        asn: int,
        zt_network_id: str,
        node_id: str,
        assigned_ips: list[str],
    ) -> list[RouteServerSyncResult]:
        self.sync_calls.append((request_id, asn, zt_network_id, node_id, assigned_ips))
        if self.sync_error is not None:
            raise self.sync_error
        return self.sync_results


def test_successful_provisioning_transitions_request_to_active(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    provider = StubProvider()

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.ACTIVE
    assert refreshed.provisioned_at is not None
    assert refreshed.retry_count == 0
    assert refreshed.last_error is None

    membership = db_session.execute(
        select(ZtMembership).where(ZtMembership.join_request_id == request_row.id)
    ).scalar_one()
    assert membership.member_id == "member-1"
    assert membership.is_authorized is True
    assert membership.assigned_ips == ["10.0.0.1/32"]

    provisioning_actions_result = db_session.execute(
        select(AuditEvent.action)
        .where(AuditEvent.target_id == str(request_row.id))
        .order_by(AuditEvent.created_at.asc())
    ).scalars()
    provisioning_actions = list(provisioning_actions_result)
    assert "provisioning.started" in provisioning_actions
    assert "provisioning.succeeded" in provisioning_actions


def test_successful_provisioning_syncs_route_servers_when_service_provided(
    db_session: Session,
) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    provider = StubProvider()
    route_sync_service = StubRouteServerSyncService()

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
        route_server_sync_service=route_sync_service,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.ACTIVE
    assert len(route_sync_service.sync_calls) == 1

    sync_events = (
        db_session.execute(
            select(AuditEvent)
            .where(
                AuditEvent.action == "route_server.sync.succeeded",
                AuditEvent.target_id == str(request_row.id),
            )
            .order_by(AuditEvent.created_at.asc())
        )
        .scalars()
        .all()
    )
    assert len(sync_events) == 1
    assert sync_events[0].event_metadata["server_count"] == 1


def test_route_server_sync_failure_sets_request_failed(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    provider = StubProvider()
    route_sync_service = StubRouteServerSyncService(
        sync_error=RouteServerSyncError("rs2 unavailable"),
    )

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
        route_server_sync_service=route_sync_service,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.FAILED
    assert refreshed.retry_count == 1
    assert refreshed.last_error is not None
    assert refreshed.last_error.startswith("route_server_sync_error")


def test_missing_node_id_fails_with_actionable_error(db_session: Session) -> None:
    request_row = _seed_join_request(db_session, status=RequestStatus.APPROVED, node_id=None)
    provider = StubProvider()

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.FAILED
    assert refreshed.retry_count == 1
    assert refreshed.last_error is not None
    assert "node_id is required" in refreshed.last_error

    membership_count = db_session.execute(
        select(func.count())
        .select_from(ZtMembership)
        .where(ZtMembership.join_request_id == request_row.id)
    ).scalar_one()
    assert membership_count == 0


def test_provider_network_failure_sets_failed_status_and_retry_count(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    provider = StubProvider(network_exists=False)

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.FAILED
    assert refreshed.retry_count == 1
    assert refreshed.last_error is not None
    assert refreshed.last_error.startswith("provider_network_not_found")


def test_provider_auth_failure_sets_failed_status_and_retry_count(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    provider = StubProvider(authorize_error=ProviderAuthError("token rejected", status_code=401))

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.FAILED
    assert refreshed.retry_count == 1
    assert refreshed.last_error is not None
    assert refreshed.last_error.startswith("provider_auth_error")


def test_existing_membership_row_is_upserted_without_duplication(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        status=RequestStatus.APPROVED,
        node_id="abcde12345",
    )
    db_session.add(
        ZtMembership(
            join_request_id=request_row.id,
            zt_network_id=request_row.zt_network_id,
            node_id="abcde12345",
            member_id="old-member",
            is_authorized=False,
            assigned_ips=["10.0.0.10/32"],
        )
    )
    db_session.commit()

    provider = StubProvider(
        authorize_result=ProvisionResult(
            member_id="new-member",
            is_authorized=True,
            assigned_ips=["10.0.0.20/32"],
            provider_name="stub_provider",
        )
    )

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    membership_rows = db_session.execute(
        select(ZtMembership).where(ZtMembership.join_request_id == request_row.id)
    ).scalars()
    membership_list = list(membership_rows)
    assert len(membership_list) == 1
    assert membership_list[0].member_id == "new-member"
    assert membership_list[0].assigned_ips == ["10.0.0.20/32"]


def test_non_approved_request_is_skipped_without_provider_calls(db_session: Session) -> None:
    request_row = _seed_join_request(db_session, status=RequestStatus.PENDING, node_id="abcde12345")
    provider = StubProvider()

    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.PENDING
    assert provider.validate_calls == []
    assert provider.authorize_calls == []

    skipped = db_session.execute(
        select(AuditEvent)
        .where(
            AuditEvent.action == "provisioning.skipped",
            AuditEvent.target_id == str(request_row.id),
        )
        .order_by(AuditEvent.created_at.asc())
    ).scalars()
    assert len(list(skipped)) == 1


def test_failed_request_can_retry_after_admin_requeue(db_session: Session) -> None:
    request_row = _seed_join_request(db_session, status=RequestStatus.FAILED, node_id="abcde12345")
    JoinRequestRepository(db_session).transition_status(request_row, RequestStatus.APPROVED)
    db_session.commit()

    provider = StubProvider(
        authorize_result=ProvisionResult(
            member_id="retry-member",
            is_authorized=True,
            assigned_ips=["10.0.0.30/32"],
            provider_name="stub_provider",
        )
    )
    process_join_request_provisioning_with_provider(
        db_session=db_session,
        request_id=request_row.id,
        provider=provider,
    )

    refreshed = db_session.get(JoinRequest, request_row.id)
    assert refreshed is not None
    assert refreshed.status is RequestStatus.ACTIVE
    assert refreshed.retry_count == 0
    assert refreshed.last_error is None


def _seed_join_request(
    db_session: Session,
    *,
    status: RequestStatus,
    node_id: str | None,
) -> JoinRequest:
    user = AppUser(peeringdb_user_id=None, username=f"user-{uuid.uuid4()}")
    network = ZtNetwork(
        id="abcdef0123456789",
        name="ZT IX Fabric",
        is_active=True,
    )
    db_session.add_all([user, network])
    db_session.flush()

    request_row = JoinRequest(
        user_id=user.id,
        asn=64512,
        zt_network_id=network.id,
        status=status,
        node_id=node_id,
    )
    db_session.add(request_row)
    db_session.commit()
    return request_row
