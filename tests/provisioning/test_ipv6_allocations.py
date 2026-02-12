from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.enums import RequestStatus
from app.db.models import AppUser, JoinRequest, ZtIpv6AllocationState, ZtNetwork
from app.repositories.ipv6_allocations import (
    Ipv6AllocationError,
    ZtIpv6AllocationRepository,
    encode_asn_decimal_split_2_4,
    parse_ipv6_prefix,
)


def test_encode_asn_decimal_split_2_4_left_zero_pads_short_asn() -> None:
    assert encode_asn_decimal_split_2_4(64512) == (6, 4512)


def test_encode_asn_decimal_split_2_4_rejects_out_of_range_asn() -> None:
    with pytest.raises(Ipv6AllocationError, match="decimal_split_2_4"):
        encode_asn_decimal_split_2_4(1_000_000)


def test_parse_ipv6_prefix_requires_64_prefix() -> None:
    with pytest.raises(Ipv6AllocationError, match="/64"):
        parse_ipv6_prefix("2001:db8:100::/56")


def test_get_or_allocate_for_request_is_idempotent(db_session: Session) -> None:
    request_row = _seed_join_request(
        db_session,
        asn=64512,
        zt_network_id="abcdef0123456789",
    )
    repository = ZtIpv6AllocationRepository(db_session)

    first = repository.get_or_allocate_for_request(
        join_request_id=request_row.id,
        zt_network_id=request_row.zt_network_id,
        asn=request_row.asn,
        network_prefix="2001:db8:100::/64",
    )
    second = repository.get_or_allocate_for_request(
        join_request_id=request_row.id,
        zt_network_id=request_row.zt_network_id,
        asn=request_row.asn,
        network_prefix="2001:db8:100::/64",
    )

    assert first.id == second.id
    assert first.sequence == 1
    assert first.assigned_ip == second.assigned_ip

    state = db_session.execute(
        select(ZtIpv6AllocationState).where(
            ZtIpv6AllocationState.zt_network_id == request_row.zt_network_id,
            ZtIpv6AllocationState.asn == request_row.asn,
        )
    ).scalar_one()
    assert state.last_sequence == 1


def test_get_or_allocate_for_request_is_monotonic_per_network_asn(
    db_session: Session,
) -> None:
    first_request = _seed_join_request(
        db_session,
        asn=64512,
        zt_network_id="abcdef0123456789",
    )
    second_request = _seed_join_request(
        db_session,
        asn=64512,
        zt_network_id="abcdef0123456789",
    )
    repository = ZtIpv6AllocationRepository(db_session)

    first = repository.get_or_allocate_for_request(
        join_request_id=first_request.id,
        zt_network_id=first_request.zt_network_id,
        asn=first_request.asn,
        network_prefix="2001:db8:100::/64",
    )
    second = repository.get_or_allocate_for_request(
        join_request_id=second_request.id,
        zt_network_id=second_request.zt_network_id,
        asn=second_request.asn,
        network_prefix="2001:db8:100::/64",
    )

    assert first.sequence == 1
    assert second.sequence == 2
    assert first.assigned_ip != second.assigned_ip

    state = db_session.execute(
        select(ZtIpv6AllocationState).where(
            ZtIpv6AllocationState.zt_network_id == first_request.zt_network_id,
            ZtIpv6AllocationState.asn == first_request.asn,
        )
    ).scalar_one()
    assert state.last_sequence == 2


def test_get_or_allocate_for_request_retries_after_integrity_contention(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_row = _seed_join_request(
        db_session,
        asn=64512,
        zt_network_id="abcdef0123456789",
    )
    repository = ZtIpv6AllocationRepository(db_session)
    original_flush = db_session.flush
    flush_count = {"value": 0}

    def flaky_flush(objects: list[Any] | tuple[Any, ...] | None = None) -> None:
        flush_count["value"] += 1
        if flush_count["value"] == 2:
            raise IntegrityError(
                "simulated concurrent insert conflict",
                params={},
                orig=Exception("duplicate assignment"),
            )
        original_flush(objects)

    monkeypatch.setattr(db_session, "flush", flaky_flush)

    assignment = repository.get_or_allocate_for_request(
        join_request_id=request_row.id,
        zt_network_id=request_row.zt_network_id,
        asn=request_row.asn,
        network_prefix="2001:db8:100::/64",
    )

    assert assignment.sequence == 1
    assert assignment.assigned_ip.startswith("2001:db8:100:")

    persisted_assignment = repository.get_by_request_id(request_row.id)
    assert persisted_assignment is not None
    assert persisted_assignment.id == assignment.id


def _seed_join_request(
    db_session: Session,
    *,
    asn: int,
    zt_network_id: str,
    node_id: str | None = None,
) -> JoinRequest:
    network = db_session.get(ZtNetwork, zt_network_id)
    if network is None:
        network = ZtNetwork(
            id=zt_network_id,
            name=f"ZT Network {zt_network_id}",
            is_active=True,
        )
        db_session.add(network)

    user = AppUser(peeringdb_user_id=None, username=f"user-{uuid.uuid4()}")
    db_session.add(user)
    db_session.flush()

    request_row = JoinRequest(
        user_id=user.id,
        asn=asn,
        zt_network_id=zt_network_id,
        status=RequestStatus.PROVISIONING,
        node_id=node_id or uuid.uuid4().hex[:10],
    )
    db_session.add(request_row)
    db_session.flush()
    return request_row
