from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


def test_api_and_worker_mount_runtime_config_for_shared_settings() -> None:
    compose = _load_compose()
    services = _services(compose)

    expected_mount = (
        "${ZTIX_RUNTIME_CONFIG_HOST_PATH:-./runtime-config.yaml}:/app/runtime-config.yaml:ro"
    )

    for service_name in ("api", "worker"):
        service = services[service_name]
        environment = _as_str_map(service.get("environment"))
        assert environment["ZTIX_RUNTIME_CONFIG_PATH"] == "/app/runtime-config.yaml"

        volumes = service.get("volumes")
        assert isinstance(volumes, list)
        assert expected_mount in volumes


def _load_compose() -> dict[str, Any]:
    compose_path = Path("docker-compose.yml")
    parsed = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _services(compose: dict[str, Any]) -> dict[str, Any]:
    services = compose.get("services")
    assert isinstance(services, dict)
    return services


def _as_str_map(value: Any) -> dict[str, str]:
    assert isinstance(value, dict)
    normalized: dict[str, str] = {}
    for key, item in value.items():
        assert isinstance(key, str)
        assert isinstance(item, str)
        normalized[key] = item
    return normalized
