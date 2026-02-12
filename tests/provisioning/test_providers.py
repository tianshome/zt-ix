from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.config import AppSettings
from app.provisioning.providers import (
    ProviderAuthError,
    ProviderNetworkNotFoundError,
    create_provisioning_provider,
)
from app.provisioning.providers.central import ZeroTierCentralProvider
from app.provisioning.providers.self_hosted_controller import (
    ZeroTierSelfHostedControllerProvider,
)


def test_factory_selects_central_provider() -> None:
    settings = _settings(zt_provider="central")

    provider = create_provisioning_provider(settings)

    assert isinstance(provider, ZeroTierCentralProvider)


def test_factory_selects_self_hosted_controller_provider() -> None:
    settings = _settings(zt_provider="self_hosted_controller")

    provider = create_provisioning_provider(settings)

    assert isinstance(provider, ZeroTierSelfHostedControllerProvider)


def test_factory_rejects_invalid_provider_mode() -> None:
    settings = _settings(zt_provider="invalid-mode")

    with pytest.raises(ValueError, match="ZT_PROVIDER must be either"):
        create_provisioning_provider(settings)


def test_factory_requires_provider_credentials() -> None:
    central_settings = _settings(zt_provider="central", zt_central_api_token="  ")
    controller_settings = _settings(
        zt_provider="self_hosted_controller",
        zt_controller_auth_token="",
    )

    with pytest.raises(ValueError, match="ZT_CENTRAL_API_TOKEN"):
        create_provisioning_provider(central_settings)

    with pytest.raises(ValueError, match="ZT_CONTROLLER_AUTH_TOKEN"):
        create_provisioning_provider(controller_settings)


def test_factory_reads_self_hosted_token_from_file(tmp_path: Path) -> None:
    token_file = tmp_path / "controller_token.secret"
    token_file.write_text("token-from-file\n", encoding="utf-8")
    settings = _settings(
        zt_provider="self_hosted_controller",
        zt_controller_auth_token="",
        zt_controller_auth_token_file=str(token_file),
    )

    provider = create_provisioning_provider(settings)

    assert isinstance(provider, ZeroTierSelfHostedControllerProvider)


@pytest.mark.parametrize(
    ("provider", "expected_header", "expected_value"),
    [
        (
            "central",
            "Authorization",
            "token token-central",
        ),
        (
            "self_hosted_controller",
            "X-ZT1-Auth",
            "token-controller",
        ),
    ],
)
def test_validate_network_uses_expected_auth_header(
    provider: str,
    expected_header: str,
    expected_value: str,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status_code=200, json={"id": "network"})

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )
    assert adapter.validate_network("abcdef0123456789") is True
    assert len(seen) == 1
    assert seen[0].headers[expected_header] == expected_value


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_validate_network_returns_false_for_404(provider: str) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=404, json={"error": "not found"})

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )

    assert adapter.validate_network("abcdef0123456789") is False


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_authorize_member_returns_normalized_result(provider: str) -> None:
    response_body = {
        "id": "member-123",
        "authorized": True,
        "config": {"ipAssignments": ["10.0.0.1/32", "10.0.0.1/32", "10.0.0.2/32"]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path.endswith("/network/abcdef0123456789/member/abcde12345")
        assert request.read().decode("utf-8") == "{\"authorized\":true}"
        return httpx.Response(status_code=200, json=response_body)

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )

    result = adapter.authorize_member(
        zt_network_id="abcdef0123456789",
        node_id="abcde12345",
        asn=64512,
        request_id=uuid.uuid4(),
    )

    assert result.member_id == "member-123"
    assert result.is_authorized is True
    assert result.assigned_ips == ["10.0.0.1/32", "10.0.0.2/32"]
    assert result.provider_name == provider


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_authorize_member_falls_back_to_put_when_post_not_allowed(provider: str) -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            assert request.method == "POST"
            return httpx.Response(status_code=405, json={"error": "method not allowed"})
        assert request.method == "PUT"
        return httpx.Response(status_code=200, json={"id": "member-put", "authorized": True})

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )
    result = adapter.authorize_member(
        zt_network_id="abcdef0123456789",
        node_id="abcde12345",
        asn=64512,
        request_id=uuid.uuid4(),
    )

    assert call_count == 2
    assert result.member_id == "member-put"


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_authorize_member_uses_explicit_ip_assignments_when_provided(provider: str) -> None:
    explicit_ip = "2001:db8:100:0:6:4512:0:1/128"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.read().decode("utf-8") == (
            '{"authorized":true,"noAutoAssignIps":true,'
            '"ipAssignments":["2001:db8:100:0:6:4512:0:1/128"]}'
        )
        return httpx.Response(
            status_code=200,
            json={
                "id": "member-ipv6",
                "authorized": True,
                "config": {"ipAssignments": [explicit_ip]},
            },
        )

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )
    result = adapter.authorize_member(
        zt_network_id="abcdef0123456789",
        node_id="abcde12345",
        asn=64512,
        request_id=uuid.uuid4(),
        explicit_ip_assignments=[explicit_ip],
    )

    assert result.assigned_ips == [explicit_ip]


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_authorize_member_maps_auth_errors(provider: str) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=401, json={"error": "unauthorized"})

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )

    with pytest.raises(ProviderAuthError):
        adapter.authorize_member(
            zt_network_id="abcdef0123456789",
            node_id="abcde12345",
            asn=64512,
            request_id=uuid.uuid4(),
        )


@pytest.mark.parametrize("provider", ["central", "self_hosted_controller"])
def test_authorize_member_maps_not_found(provider: str) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=404, json={"error": "missing"})

    adapter = _provider(
        provider,
        http_client_factory=_mock_client_factory(handler),
    )

    with pytest.raises(ProviderNetworkNotFoundError):
        adapter.authorize_member(
            zt_network_id="abcdef0123456789",
            node_id="abcde12345",
            asn=64512,
            request_id=uuid.uuid4(),
        )


def _provider(
    provider_name: str,
    *,
    http_client_factory: Callable[..., httpx.Client],
) -> ZeroTierCentralProvider | ZeroTierSelfHostedControllerProvider:
    if provider_name == "central":
        return ZeroTierCentralProvider(
            base_url="https://api.zerotier.com/api/v1",
            api_token="token-central",
            http_client_factory=http_client_factory,
        )
    if provider_name == "self_hosted_controller":
        return ZeroTierSelfHostedControllerProvider(
            base_url="http://127.0.0.1:9993/controller",
            auth_token="token-controller",
            http_client_factory=http_client_factory,
        )
    raise AssertionError(f"unknown provider {provider_name}")


def _mock_client_factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[..., httpx.Client]:
    def factory(**kwargs: Any) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)

    return factory


def _settings(**overrides: Any) -> AppSettings:
    base = AppSettings(
        app_env="test",
        app_secret_key="secret",
        session_cookie_name="zt_ix_session",
        session_cookie_max_age_seconds=3600,
        session_cookie_secure=False,
        oauth_state_ttl_seconds=600,
        peeringdb_client_id="client-id",
        peeringdb_client_secret="client-secret",
        peeringdb_redirect_uri="http://testserver/auth/callback",
        peeringdb_authorization_url="https://auth.peeringdb.com/oauth2/authorize/",
        peeringdb_token_url="https://auth.peeringdb.com/oauth2/token/",
        peeringdb_profile_url="https://auth.peeringdb.com/profile/v1",
        peeringdb_scopes=("openid", "profile", "email", "networks"),
        peeringdb_http_timeout_seconds=2.0,
        local_auth_enabled=True,
        local_auth_password_min_length=12,
        local_auth_pbkdf2_iterations=100_000,
        redis_url="memory://",
        zt_provider="central",
        zt_central_base_url="https://api.zerotier.com/api/v1",
        zt_central_api_token="token-central",
        zt_controller_base_url="http://127.0.0.1:9993/controller",
        zt_controller_auth_token="token-controller",
    )
    return replace(base, **overrides)
