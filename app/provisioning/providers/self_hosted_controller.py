"""Self-hosted ZeroTier controller provisioning adapter."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import httpx

from app.provisioning.providers.base import (
    ProviderAuthError,
    ProviderNetworkNotFoundError,
    ProviderRequestError,
    ProvisionResult,
)
from app.provisioning.providers.central import (
    _build_member_authorization_payload,
    _extract_assigned_ips,
    _extract_is_authorized,
    _extract_member_id,
    _parse_json_object,
)

HTTPClientFactory = Callable[..., httpx.Client]


class ZeroTierSelfHostedControllerProvider:
    provider_name = "self_hosted_controller"

    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        timeout_seconds: float = 10.0,
        http_client_factory: HTTPClientFactory = httpx.Client,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._timeout_seconds = timeout_seconds
        self._http_client_factory = http_client_factory

    def validate_network(self, zt_network_id: str) -> bool:
        response = self._request("GET", f"/network/{zt_network_id}")
        if response.status_code == 404:
            return False
        self._raise_for_status(
            response,
            default_message="failed to validate self-hosted controller network",
        )
        return True

    def authorize_member(
        self,
        *,
        zt_network_id: str,
        node_id: str,
        asn: int,
        request_id: uuid.UUID,
        explicit_ip_assignments: list[str] | None = None,
    ) -> ProvisionResult:
        payload = _build_member_authorization_payload(
            explicit_ip_assignments=explicit_ip_assignments,
        )
        response = self._request(
            "POST",
            f"/network/{zt_network_id}/member/{node_id}",
            json_body=payload,
        )
        if response.status_code == 405:
            response = self._request(
                "PUT",
                f"/network/{zt_network_id}/member/{node_id}",
                json_body=payload,
            )
        if response.status_code == 404:
            raise ProviderNetworkNotFoundError(
                (
                    "self-hosted controller network/member not found for "
                    f"zt_network_id={zt_network_id} node_id={node_id}"
                ),
                status_code=response.status_code,
            )
        self._raise_for_status(
            response,
            default_message=(
                "failed to authorize self-hosted controller member "
                f"request_id={request_id} asn={asn}"
            ),
        )

        body = _parse_json_object(response)
        return ProvisionResult(
            member_id=_extract_member_id(body, fallback=node_id),
            is_authorized=_extract_is_authorized(body, default=True),
            assigned_ips=_extract_assigned_ips(body),
            provider_name=self.provider_name,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        with self._http_client_factory(
            base_url=self._base_url,
            headers={"X-ZT1-Auth": self._auth_token},
            timeout=self._timeout_seconds,
        ) as client:
            try:
                return client.request(method, path, json=json_body)
            except httpx.HTTPError as exc:
                raise ProviderRequestError(f"self-hosted controller request failed: {exc}") from exc

    def _raise_for_status(self, response: httpx.Response, *, default_message: str) -> None:
        if response.status_code < 400:
            return

        status_code = response.status_code
        if status_code in {401, 403}:
            raise ProviderAuthError(
                f"self-hosted controller authentication failed with status={status_code}",
                status_code=status_code,
            )

        response_text = response.text.strip()
        detail = f"{default_message}; status={status_code}"
        if response_text:
            detail = f"{detail}; body={response_text[:240]}"
        raise ProviderRequestError(detail, status_code=status_code)
