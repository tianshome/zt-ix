"""Domain enums and transition helpers."""

from enum import StrEnum


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    REJECTED = "rejected"
    FAILED = "failed"


ACTIVE_REQUEST_STATUSES = frozenset(
    {
        RequestStatus.PENDING,
        RequestStatus.APPROVED,
        RequestStatus.PROVISIONING,
        RequestStatus.ACTIVE,
    }
)

ALLOWED_STATUS_TRANSITIONS: dict[RequestStatus, frozenset[RequestStatus]] = {
    RequestStatus.PENDING: frozenset({RequestStatus.APPROVED, RequestStatus.REJECTED}),
    RequestStatus.APPROVED: frozenset({RequestStatus.PROVISIONING}),
    RequestStatus.PROVISIONING: frozenset({RequestStatus.ACTIVE, RequestStatus.FAILED}),
    RequestStatus.FAILED: frozenset({RequestStatus.APPROVED}),
}


def can_transition_status(current_status: RequestStatus, new_status: RequestStatus) -> bool:
    return new_status in ALLOWED_STATUS_TRANSITIONS.get(current_status, frozenset())
