from __future__ import annotations

import subprocess
import uuid
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

import pytest

from app.config import AppSettings
from app.provisioning.route_servers import (
    RouteServerConfigInputError,
    RouteServerSyncError,
    create_route_server_sync_service,
    render_bird_peer_config,
)


def test_render_bird_peer_config_includes_roa_checks_and_peer_stanzas() -> None:
    rendered = render_bird_peer_config(
        request_id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        asn=64512,
        zt_network_id="abcdef0123456789",
        node_id="abcde12345",
        assigned_ips=["2001:db8::2/128", "10.10.10.2/32", "10.10.10.2/32"],
        route_server_local_asn=65010,
    )

    assert "roa_check(ztix_roa_v4, net, bgp_path.last)" in rendered
    assert "roa_check(ztix_roa_v6, net, bgp_path.last)" in rendered
    assert "neighbor 10.10.10.2 as 64512;" in rendered
    assert "neighbor 2001:db8::2 as 64512;" in rendered
    assert rendered.count("protocol bgp") == 2


def test_sync_desired_config_fans_out_and_applies_on_all_configured_route_servers() -> None:
    calls: list[tuple[list[str], str | None]] = []

    def command_runner(
        command: Sequence[str],
        stdin_data: str | None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((list(command), stdin_data))
        return subprocess.CompletedProcess(args=list(command), returncode=0, stdout="", stderr="")

    settings = _settings(
        route_server_hosts=("rs1.example.net", "rs2.example.net"),
        route_server_ssh_user="ztix",
    )
    service = create_route_server_sync_service(settings, command_runner=command_runner)
    request_id = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    results = service.sync_desired_config(
        request_id=request_id,
        asn=64512,
        zt_network_id="abcdef0123456789",
        node_id="abcde12345",
        assigned_ips=["10.0.0.2/32"],
    )

    assert len(results) == 2
    assert all(result.host in {"rs1.example.net", "rs2.example.net"} for result in results)
    assert all(
        result.remote_path.endswith(f"ztix_as64512_req_{request_id.hex}.conf")
        for result in results
    )
    assert all(result.apply_confirmed is True for result in results)
    assert len(calls) == 16
    assert calls[0][0][-2] == "ztix@rs1.example.net"
    assert calls[8][0][-2] == "ztix@rs2.example.net"
    write_payloads = [
        stdin_data for command, stdin_data in calls if command[-1].startswith("cat > ")
    ]
    assert len(write_payloads) == 2
    assert write_payloads[0] is not None
    assert "protocol bgp" in write_payloads[0]
    rs1_commands = [command[-1] for command, _ in calls if command[-2] == "ztix@rs1.example.net"]
    assert "bird -p -c /etc/bird/bird.conf" in rs1_commands
    assert "birdc configure check" in rs1_commands
    assert "timeout 20s birdc configure" in rs1_commands
    assert "birdc show status" in rs1_commands


def test_sync_desired_config_rolls_back_failed_host_and_aggregates_outcomes() -> None:
    calls: list[tuple[list[str], str | None]] = []

    def command_runner(
        command: Sequence[str],
        stdin_data: str | None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((list(command), stdin_data))
        if command[-2] == "ztix@rs2.example.net" and command[-1] == "birdc configure check":
            return subprocess.CompletedProcess(
                args=list(command),
                returncode=1,
                stdout="",
                stderr="birdc check failed",
            )
        return subprocess.CompletedProcess(args=list(command), returncode=0, stdout="", stderr="")

    settings = _settings(
        route_server_hosts=("rs1.example.net", "rs2.example.net"),
        route_server_ssh_user="ztix",
    )
    service = create_route_server_sync_service(settings, command_runner=command_runner)

    with pytest.raises(RouteServerSyncError, match="rs2.example.net") as exc_info:
        service.sync_desired_config(
            request_id=uuid.uuid4(),
            asn=64512,
            zt_network_id="abcdef0123456789",
            node_id="abcde12345",
            assigned_ips=["10.0.0.2/32"],
        )
    exc = exc_info.value
    assert len(exc.successful_results) == 1
    assert exc.successful_results[0].host == "rs1.example.net"
    assert len(exc.host_failures) == 1
    failure = exc.host_failures[0]
    assert failure.host == "rs2.example.net"
    assert failure.stage == "birdc_configure_check"
    assert failure.rollback_attempted is True
    assert failure.rollback_succeeded is True

    rs2_commands = [command[-1] for command, _ in calls if command[-2] == "ztix@rs2.example.net"]
    assert "birdc configure check" in rs2_commands
    assert any(command.startswith("if [ -f ") and ".bak" in command for command in rs2_commands)
    assert "timeout 20s birdc configure" in rs2_commands


def test_render_bird_peer_config_requires_assigned_endpoint_ip() -> None:
    with pytest.raises(RouteServerConfigInputError, match="at least one assigned IP"):
        render_bird_peer_config(
            request_id=uuid.uuid4(),
            asn=64512,
            zt_network_id="abcdef0123456789",
            node_id="abcde12345",
            assigned_ips=[],
            route_server_local_asn=65010,
        )


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
        route_server_hosts=(),
        route_server_ssh_user="root",
        route_server_ssh_port=22,
        route_server_ssh_private_key_path="",
        route_server_ssh_connect_timeout_seconds=10.0,
        route_server_ssh_strict_host_key=True,
        route_server_ssh_known_hosts_file="",
        route_server_remote_config_dir="/etc/bird/ztix-peers.d",
        route_server_local_asn=65000,
    )
    return replace(base, **overrides)
