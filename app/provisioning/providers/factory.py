"""Provisioning provider selection based on runtime settings."""

from __future__ import annotations

from app.config import AppSettings
from app.provisioning.controller_auth import resolve_controller_auth_token
from app.provisioning.providers.base import ProvisioningProvider
from app.provisioning.providers.central import ZeroTierCentralProvider
from app.provisioning.providers.self_hosted_controller import (
    ZeroTierSelfHostedControllerProvider,
)


def create_provisioning_provider(settings: AppSettings) -> ProvisioningProvider:
    provider_mode = settings.zt_provider.strip().lower()
    if provider_mode == "central":
        token = settings.zt_central_api_token.strip()
        if not token:
            raise ValueError("ZT_CENTRAL_API_TOKEN is required when ZT_PROVIDER=central")
        base_url = settings.zt_central_base_url.strip()
        if not base_url:
            raise ValueError("ZT_CENTRAL_BASE_URL is required when ZT_PROVIDER=central")
        return ZeroTierCentralProvider(base_url=base_url, api_token=token)

    if provider_mode == "self_hosted_controller":
        token = resolve_controller_auth_token(settings)
        base_url = settings.zt_controller_base_url.strip()
        if not base_url:
            raise ValueError(
                "ZT_CONTROLLER_BASE_URL is required when ZT_PROVIDER=self_hosted_controller"
            )
        return ZeroTierSelfHostedControllerProvider(base_url=base_url, auth_token=token)

    raise ValueError(
        "ZT_PROVIDER must be either 'central' or 'self_hosted_controller' "
        f"(received {settings.zt_provider!r})"
    )
