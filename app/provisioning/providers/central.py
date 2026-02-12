"""ZeroTier Central provisioning adapter."""

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

HTTPClientFactory = Callable[..., httpx.Client]


class ZeroTierCentralProvider:
    provider_name = "central"

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        timeout_seconds: float = 10.0,
        http_client_factory: HTTPClientFactory = httpx.Client,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._timeout_seconds = timeout_seconds
        self._http_client_factory = http_client_factory

    def validate_network(self, zt_network_id: str) -> bool:
        response = self._request("GET", f"/network/{zt_network_id}")
        if response.status_code == 404:
            return False
        self._raise_for_status(
            response,
            default_message="failed to validate ZeroTier Central network",
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
                    "central network/member not found for "
                    f"zt_network_id={zt_network_id} node_id={node_id}"
                ),
                status_code=response.status_code,
            )
        self._raise_for_status(
            response,
            default_message=(
                "failed to authorize ZeroTier Central member "
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
            headers={"Authorization": f"token {self._api_token}"},
            timeout=self._timeout_seconds,
        ) as client:
            try:
                return client.request(method, path, json=json_body)
            except httpx.HTTPError as exc:
                raise ProviderRequestError(f"central request failed: {exc}") from exc

    def _raise_for_status(self, response: httpx.Response, *, default_message: str) -> None:
        if response.status_code < 400:
            return

        status_code = response.status_code
        if status_code in {401, 403}:
            raise ProviderAuthError(
                f"central authentication failed with status={status_code}",
                status_code=status_code,
            )

        response_text = response.text.strip()
        detail = f"{default_message}; status={status_code}"
        if response_text:
            detail = f"{detail}; body={response_text[:240]}"
        raise ProviderRequestError(detail, status_code=status_code)


def _build_member_authorization_payload(
    *,
    explicit_ip_assignments: list[str] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"authorized": True}
    if explicit_ip_assignments:
        payload["noAutoAssignIps"] = True
        payload["ipAssignments"] = explicit_ip_assignments
    return payload


def _parse_json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise ProviderRequestError(
            f"central response was not valid JSON (status={response.status_code})",
            status_code=response.status_code,
        ) from exc

    if not isinstance(data, dict):
        raise ProviderRequestError(
            f"central response payload must be an object (status={response.status_code})",
            status_code=response.status_code,
        )
    return data


def _extract_member_id(payload: dict[str, Any], *, fallback: str) -> str:
    for key in ("id", "memberId", "member_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _extract_is_authorized(payload: dict[str, Any], *, default: bool) -> bool:
    value = payload.get("authorized")
    if isinstance(value, bool):
        return value

    config = payload.get("config")
    if isinstance(config, dict):
        config_authorized = config.get("authorized")
        if isinstance(config_authorized, bool):
            return config_authorized
    return default


def _extract_assigned_ips(payload: dict[str, Any]) -> list[str]:
    candidates: Any = payload.get("ipAssignments")
    if candidates is None:
        config = payload.get("config")
        if isinstance(config, dict):
            candidates = config.get("ipAssignments")

    if not isinstance(candidates, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized
