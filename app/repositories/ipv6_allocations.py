"""Repository helpers for deterministic IPv6 allocation persistence."""

from __future__ import annotations

import ipaddress
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import ZtIpv6AllocationState, ZtIpv6Assignment

_MAX_DECIMAL_SPLIT_2_4_ASN = 999_999
_MAX_IPV6_SEQUENCE = 0xFFFFFFFF
_MAX_ALLOCATION_ATTEMPTS = 6


class Ipv6AllocationError(Exception):
    """Raised when deterministic IPv6 allocation cannot be completed."""

    error_code = "ipv6_allocation_error"


class ZtIpv6AllocationRepository:
    """Allocates and persists never-reused IPv6 assignments per request."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_request_id(self, join_request_id: uuid.UUID) -> ZtIpv6Assignment | None:
        statement = select(ZtIpv6Assignment).where(
            ZtIpv6Assignment.join_request_id == join_request_id
        )
        return self._session.execute(statement).scalar_one_or_none()

    def get_or_allocate_for_request(
        self,
        *,
        join_request_id: uuid.UUID,
        zt_network_id: str,
        asn: int,
        network_prefix: str,
    ) -> ZtIpv6Assignment:
        existing = self.get_by_request_id(join_request_id)
        if existing is not None:
            return existing

        parsed_prefix = parse_ipv6_prefix(network_prefix)
        asn_prefix, asn_suffix = encode_asn_decimal_split_2_4(asn)

        for _ in range(_MAX_ALLOCATION_ATTEMPTS):
            try:
                with self._session.begin_nested():
                    existing = self.get_by_request_id(join_request_id)
                    if existing is not None:
                        return existing

                    state = self._select_state_for_update(
                        zt_network_id=zt_network_id,
                        asn=asn,
                    )
                    if state is None:
                        state = ZtIpv6AllocationState(
                            zt_network_id=zt_network_id,
                            asn=asn,
                            last_sequence=0,
                        )
                        self._session.add(state)
                        self._session.flush()

                    next_sequence = int(state.last_sequence) + 1
                    if next_sequence > _MAX_IPV6_SEQUENCE:
                        raise Ipv6AllocationError(
                            "IPv6 allocation sequence exhausted for "
                            f"zt_network_id={zt_network_id} asn={asn}"
                        )

                    assigned_ip = deterministic_ipv6_address(
                        prefix=parsed_prefix,
                        asn_prefix=asn_prefix,
                        asn_suffix=asn_suffix,
                        sequence=next_sequence,
                    )
                    state.last_sequence = next_sequence

                    assignment = ZtIpv6Assignment(
                        join_request_id=join_request_id,
                        zt_network_id=zt_network_id,
                        asn=asn,
                        sequence=next_sequence,
                        assigned_ip=assigned_ip,
                    )
                    self._session.add(assignment)
                    self._session.flush()
                    return assignment
            except IntegrityError:
                existing = self.get_by_request_id(join_request_id)
                if existing is not None:
                    return existing
                continue

        raise Ipv6AllocationError(
            "failed to allocate deterministic IPv6 address after repeated "
            f"contention for zt_network_id={zt_network_id} asn={asn}"
        )

    def _select_state_for_update(
        self,
        *,
        zt_network_id: str,
        asn: int,
    ) -> ZtIpv6AllocationState | None:
        statement = (
            select(ZtIpv6AllocationState)
            .where(
                ZtIpv6AllocationState.zt_network_id == zt_network_id,
                ZtIpv6AllocationState.asn == asn,
            )
            .with_for_update()
        )
        return self._session.execute(statement).scalar_one_or_none()


def parse_ipv6_prefix(prefix: str) -> ipaddress.IPv6Network:
    normalized = prefix.strip()
    if not normalized:
        raise Ipv6AllocationError("IPv6 prefix is required")
    try:
        parsed = ipaddress.IPv6Network(normalized, strict=True)
    except ValueError as exc:
        raise Ipv6AllocationError(f"invalid IPv6 prefix {prefix!r}") from exc
    if parsed.prefixlen != 64:
        raise Ipv6AllocationError(
            f"IPv6 prefix must be /64 for deterministic allocation: {normalized!r}"
        )
    return parsed


def encode_asn_decimal_split_2_4(asn: int) -> tuple[int, int]:
    if asn <= 0:
        raise Ipv6AllocationError(f"ASN must be positive for IPv6 allocation: {asn}")
    if asn > _MAX_DECIMAL_SPLIT_2_4_ASN:
        raise Ipv6AllocationError(
            "ASN exceeds decimal_split_2_4 range (max 999999): "
            f"{asn}"
        )

    # Fixed encoding contract: decimal string left-padded to 6 chars, split 2 + 4.
    encoded = f"{asn:06d}"
    return int(encoded[:2]), int(encoded[2:])


def deterministic_ipv6_address(
    *,
    prefix: ipaddress.IPv6Network,
    asn_prefix: int,
    asn_suffix: int,
    sequence: int,
) -> str:
    if sequence <= 0:
        raise Ipv6AllocationError(f"IPv6 sequence must be positive: {sequence}")
    if sequence > _MAX_IPV6_SEQUENCE:
        raise Ipv6AllocationError(f"IPv6 sequence exceeds supported range: {sequence}")

    interface_identifier = (asn_prefix << 48) | (asn_suffix << 32) | sequence
    host_bits = 128 - prefix.prefixlen
    if interface_identifier >= (1 << host_bits):
        raise Ipv6AllocationError(
            "computed deterministic interface identifier exceeds network host space"
        )

    assigned = ipaddress.IPv6Address(int(prefix.network_address) + interface_identifier)
    return f"{assigned.compressed}/128"
