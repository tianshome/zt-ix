"""Repository-level domain errors."""

from app.db.enums import RequestStatus


class RepositoryError(Exception):
    """Base repository exception."""


class DuplicateActiveRequestError(RepositoryError):
    """Raised when an active join request already exists for ASN/network/node identity."""


class InvalidStateTransitionError(RepositoryError):
    """Raised when a join-request status transition is not allowed."""

    def __init__(self, current_status: RequestStatus, new_status: RequestStatus) -> None:
        message = (
            f"cannot transition join request from {current_status.value} "
            f"to {new_status.value}"
        )
        super().__init__(message)
        self.current_status = current_status
        self.new_status = new_status
