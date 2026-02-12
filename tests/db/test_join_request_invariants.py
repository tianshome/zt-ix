from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.db.enums import RequestStatus
from app.db.models import AppUser, ZtNetwork
from app.repositories.errors import DuplicateActiveRequestError, InvalidStateTransitionError
from app.repositories.join_requests import JoinRequestRepository


def _seed_user_and_network(session: Session) -> tuple[uuid.UUID, str]:
    user = AppUser(peeringdb_user_id=12345, username="operator-one", full_name="Operator One")
    network = ZtNetwork(id="abcdef0123456789", name="ZT-IX Fabric")
    session.add_all([user, network])
    session.flush()
    return user.id, network.id


def test_unique_active_request_per_asn_network_and_node_id(db_session: Session) -> None:
    user_id, network_id = _seed_user_and_network(db_session)
    repo = JoinRequestRepository(db_session)

    first_request = repo.create_pending_request(
        user_id=user_id,
        asn=64512,
        zt_network_id=network_id,
        node_id="abcde12345",
    )
    second_request = repo.create_pending_request(
        user_id=user_id,
        asn=64512,
        zt_network_id=network_id,
        node_id="ffffe12345",
    )
    assert second_request.id != first_request.id

    with pytest.raises(DuplicateActiveRequestError):
        repo.create_pending_request(
            user_id=user_id,
            asn=64512,
            zt_network_id=network_id,
            node_id="abcde12345",
        )

    repo.transition_status(
        first_request,
        RequestStatus.REJECTED,
        reject_reason="manual reject to free active slot",
    )
    replacement = repo.create_pending_request(
        user_id=user_id,
        asn=64512,
        zt_network_id=network_id,
        node_id="abcde12345",
    )

    assert replacement.id != first_request.id
    assert replacement.status is RequestStatus.PENDING

    repo.create_pending_request(user_id=user_id, asn=64513, zt_network_id=network_id)
    with pytest.raises(DuplicateActiveRequestError):
        repo.create_pending_request(user_id=user_id, asn=64513, zt_network_id=network_id)


def test_join_request_transition_rules(db_session: Session) -> None:
    user_id, network_id = _seed_user_and_network(db_session)
    repo = JoinRequestRepository(db_session)
    request = repo.create_pending_request(user_id=user_id, asn=64513, zt_network_id=network_id)

    repo.transition_status(request, RequestStatus.APPROVED)
    repo.transition_status(request, RequestStatus.PROVISIONING)
    repo.transition_status(
        request,
        RequestStatus.FAILED,
        last_error="upstream timeout",
        increment_retry=True,
    )
    assert request.retry_count == 1

    repo.transition_status(request, RequestStatus.APPROVED)
    assert request.status is RequestStatus.APPROVED

    with pytest.raises(InvalidStateTransitionError):
        repo.transition_status(request, RequestStatus.ACTIVE)
