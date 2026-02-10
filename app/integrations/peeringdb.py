"""PeeringDB OAuth/profile client and payload normalization."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.config import AppSettings

_READ_PERMISSION_BIT = 0b0100


class PeeringDBClientError(Exception):
    """Base PeeringDB client exception."""


class PeeringDBTokenExchangeError(PeeringDBClientError):
    """Raised when token exchange fails."""


class PeeringDBProfileError(PeeringDBClientError):
    """Raised when profile retrieval or parsing fails."""


class PeeringDBNonceValidationError(PeeringDBClientError):
    """Raised when nonce validation fails."""


@dataclass(frozen=True, slots=True)
class PeeringDBTokenResponse:
    access_token: str
    id_token: str | None = None


@dataclass(frozen=True, slots=True)
class PeeringDBNetwork:
    asn: int
    net_id: int | None
    net_name: str | None
    perms: int | None


@dataclass(frozen=True, slots=True)
class PeeringDBUserProfile:
    peeringdb_user_id: int
    username: str
    full_name: str | None
    email: str | None
    networks: tuple[PeeringDBNetwork, ...]

    @property
    def authorized_networks(self) -> tuple[PeeringDBNetwork, ...]:
        return tuple(network for network in self.networks if _has_read_permission(network.perms))


class PeeringDBClientProtocol(Protocol):
    async def exchange_code_for_tokens(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> PeeringDBTokenResponse: ...

    async def fetch_profile(self, *, access_token: str) -> PeeringDBUserProfile: ...


class PeeringDBClient(PeeringDBClientProtocol):
    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings

    async def exchange_code_for_tokens(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> PeeringDBTokenResponse:
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._settings.peeringdb_client_id,
            "client_secret": self._settings.peeringdb_client_secret,
            "code_verifier": code_verifier,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self._settings.peeringdb_http_timeout_seconds
            ) as client:
                response = await client.post(self._settings.peeringdb_token_url, data=payload)
        except httpx.RequestError as exc:
            raise PeeringDBTokenExchangeError("token exchange request failed") from exc

        if response.status_code >= 400:
            raise PeeringDBTokenExchangeError(
                f"token exchange failed with status={response.status_code}"
            )

        data = _json_object(response, error_cls=PeeringDBTokenExchangeError)
        access_token = data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise PeeringDBTokenExchangeError("token exchange response missing access_token")

        id_token = data.get("id_token")
        if id_token is not None and not isinstance(id_token, str):
            raise PeeringDBTokenExchangeError("token exchange response has invalid id_token")

        return PeeringDBTokenResponse(access_token=access_token, id_token=id_token)

    async def fetch_profile(self, *, access_token: str) -> PeeringDBUserProfile:
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            async with httpx.AsyncClient(
                timeout=self._settings.peeringdb_http_timeout_seconds
            ) as client:
                response = await client.get(self._settings.peeringdb_profile_url, headers=headers)
        except httpx.RequestError as exc:
            raise PeeringDBProfileError("profile request failed") from exc

        if response.status_code >= 400:
            raise PeeringDBProfileError(
                f"profile request failed with status={response.status_code}"
            )

        data = _json_object(response, error_cls=PeeringDBProfileError)
        return parse_profile_payload(data)


def validate_id_token_nonce(*, id_token: str | None, expected_nonce: str) -> None:
    if not id_token:
        raise PeeringDBNonceValidationError("missing id_token for nonce validation")

    payload = _decode_jwt_payload(id_token)
    token_nonce = payload.get("nonce")
    if not isinstance(token_nonce, str):
        raise PeeringDBNonceValidationError("id_token nonce claim missing")
    if token_nonce != expected_nonce:
        raise PeeringDBNonceValidationError("id_token nonce mismatch")


def parse_profile_payload(data: Mapping[str, Any]) -> PeeringDBUserProfile:
    peeringdb_user_id = _coerce_required_int(data, "id")

    full_name = _coerce_optional_str(data.get("name"))
    username = _coerce_optional_str(data.get("username"))
    if not username:
        username = full_name or f"pdb-{peeringdb_user_id}"

    email = _coerce_optional_str(data.get("email"))

    raw_networks = data.get("networks")
    networks: list[PeeringDBNetwork] = []
    if isinstance(raw_networks, list):
        for item in raw_networks:
            if not isinstance(item, Mapping):
                continue

            asn = _coerce_required_int(item, "asn")

            net_id = _coerce_optional_int(item.get("id"))
            net_name = _coerce_optional_str(item.get("name"))
            perms = _coerce_optional_int(item.get("perms"))
            networks.append(
                PeeringDBNetwork(
                    asn=asn,
                    net_id=net_id,
                    net_name=net_name,
                    perms=perms,
                )
            )

    return PeeringDBUserProfile(
        peeringdb_user_id=peeringdb_user_id,
        username=username,
        full_name=full_name,
        email=email,
        networks=tuple(networks),
    )


def _decode_jwt_payload(token: str) -> Mapping[str, Any]:
    segments = token.split(".")
    if len(segments) < 2:
        raise PeeringDBNonceValidationError("invalid id_token format")

    payload_segment = segments[1]
    padding = "=" * (-len(payload_segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(f"{payload_segment}{padding}".encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise PeeringDBNonceValidationError("invalid id_token payload") from exc

    if not isinstance(payload, Mapping):
        raise PeeringDBNonceValidationError("invalid id_token payload")
    return payload


def _json_object(
    response: httpx.Response,
    *,
    error_cls: type[PeeringDBClientError],
) -> Mapping[str, Any]:
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise error_cls("upstream response is not valid JSON") from exc

    if not isinstance(data, Mapping):
        raise error_cls("upstream response root must be a JSON object")
    return data


def _coerce_required_int(data: Mapping[str, Any], key: str) -> int:
    raw_value = data.get(key)
    value = _coerce_optional_int(raw_value)
    if value is None:
        raise PeeringDBProfileError(f"profile field '{key}' must be an integer")
    return value


def _coerce_optional_int(value: Any) -> int | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None

    return None


def _coerce_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _has_read_permission(perms: int | None) -> bool:
    if perms is None:
        return True
    return (perms & _READ_PERMISSION_BIT) != 0
