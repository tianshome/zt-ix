"""Provisioning provider interface and normalized result model."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class ProvisionResult:
    member_id: str
    is_authorized: bool
    assigned_ips: list[str]
    provider_name: str


class ProvisioningProvider(Protocol):
    provider_name: str

    def validate_network(self, zt_network_id: str) -> bool:
        """Return True when the target network exists and is available."""

    def authorize_member(
        self,
        *,
        zt_network_id: str,
        node_id: str,
        asn: int,
        request_id: uuid.UUID,
        explicit_ip_assignments: list[str] | None = None,
    ) -> ProvisionResult:
        """Authorize a member and return a normalized provider result."""


class ProvisioningProviderError(Exception):
    """Base provider exception for deterministic failure handling."""

    error_code = "provider_error"

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ProviderAuthError(ProvisioningProviderError):
    error_code = "provider_auth_error"


class ProviderNetworkNotFoundError(ProvisioningProviderError):
    error_code = "provider_network_not_found"


class ProviderRequestError(ProvisioningProviderError):
    error_code = "provider_request_error"
