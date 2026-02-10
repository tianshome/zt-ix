from __future__ import annotations

import ast
import os
import re
import shlex
import subprocess
import uuid
from pathlib import Path

import pytest

from app.provisioning.route_servers import RouteServerSyncService, render_bird_peer_config


def test_live_route_server_creates_test_bgp_session() -> None:
    if os.getenv("ZTIX_RUN_ROUTE_SERVER_INTEGRATION") != "1":
        pytest.skip("set ZTIX_RUN_ROUTE_SERVER_INTEGRATION=1 to run live route-server integration")

    runtime_config_path = Path(os.getenv("ZTIX_RUNTIME_CONFIG_PATH", "runtime-config.yaml"))
    if not runtime_config_path.exists():
        pytest.skip(f"runtime config not found: {runtime_config_path}")

    route_server_config = _load_route_server_config(runtime_config_path)
    if not route_server_config.hosts:
        pytest.skip("no route server hosts configured")

    ssh_key_path = Path(
        os.getenv("ZTIX_ROUTE_SERVER_TEST_SSH_KEY_PATH", route_server_config.ssh_private_key_path)
    )
    if not ssh_key_path.exists():
        pytest.skip(f"ssh key not found for integration test: {ssh_key_path}")

    host = route_server_config.hosts[0]
    known_hosts_path = Path("/tmp/ztix_route_server_integration_known_hosts")
    _populate_known_hosts(
        host=host,
        port=route_server_config.ssh_port,
        output_path=known_hosts_path,
    )

    request_id = uuid.uuid4()
    asn = 64590
    zt_network_id = "abcdef0123456789"
    node_id = "abcde12345"
    assigned_ips = ["203.0.113.10/32"]

    service = RouteServerSyncService(
        route_server_hosts=(host,),
        ssh_user=route_server_config.ssh_user,
        ssh_port=route_server_config.ssh_port,
        ssh_private_key_path=str(ssh_key_path),
        ssh_connect_timeout_seconds=route_server_config.ssh_connect_timeout_seconds,
        ssh_strict_host_key=True,
        ssh_known_hosts_file=str(known_hosts_path),
        remote_config_dir=route_server_config.remote_config_dir,
        route_server_local_asn=route_server_config.route_server_local_asn,
    )
    remote_path = f"{route_server_config.remote_config_dir}/ztix_as{asn}_req_{request_id.hex}.conf"
    rendered = render_bird_peer_config(
        request_id=request_id,
        asn=asn,
        zt_network_id=zt_network_id,
        node_id=node_id,
        assigned_ips=assigned_ips,
        route_server_local_asn=route_server_config.route_server_local_asn,
    )
    protocol_names = _extract_protocol_names(rendered)
    assert protocol_names

    test_error: BaseException | None = None
    try:
        results = service.sync_desired_config(
            request_id=request_id,
            asn=asn,
            zt_network_id=zt_network_id,
            node_id=node_id,
            assigned_ips=assigned_ips,
        )
        assert len(results) == 1
        assert results[0].host == host
        assert results[0].apply_confirmed is True
        assert results[0].remote_path == remote_path

        protocol_output = _run_ssh_command(
            host=host,
            user=route_server_config.ssh_user,
            port=route_server_config.ssh_port,
            key_path=ssh_key_path,
            known_hosts_path=known_hosts_path,
            connect_timeout_seconds=route_server_config.ssh_connect_timeout_seconds,
            remote_command=f"birdc show protocols all {protocol_names[0]}",
        )
        assert protocol_names[0] in protocol_output
        assert "BGP" in protocol_output
    except BaseException as exc:
        test_error = exc
    finally:
        cleanup_command = (
            f"rm -f {shlex.quote(remote_path)} {shlex.quote(remote_path + '.bak')} "
            f"{shlex.quote(remote_path + '.candidate')} && birdc configure check "
            "&& timeout 20s birdc configure"
        )
        try:
            _run_ssh_command(
                host=host,
                user=route_server_config.ssh_user,
                port=route_server_config.ssh_port,
                key_path=ssh_key_path,
                known_hosts_path=known_hosts_path,
                connect_timeout_seconds=route_server_config.ssh_connect_timeout_seconds,
                remote_command=cleanup_command,
            )
        except AssertionError:
            if test_error is None:
                raise
        if test_error is not None:
            raise test_error


def _populate_known_hosts(*, host: str, port: int, output_path: Path) -> None:
    result = subprocess.run(
        ["ssh-keyscan", "-p", str(port), host],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "no output"
        raise AssertionError(f"ssh-keyscan failed for host={host}: {detail}")
    output_path.write_text(result.stdout)


def _run_ssh_command(
    *,
    host: str,
    user: str,
    port: int,
    key_path: Path,
    known_hosts_path: Path,
    connect_timeout_seconds: float,
    remote_command: str,
) -> str:
    target = f"{user}@{host}" if user else host
    command = [
        "ssh",
        "-p",
        str(port),
        "-i",
        str(key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={int(connect_timeout_seconds)}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        target,
        remote_command,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "no output"
        raise AssertionError(
            "ssh command failed for "
            f"host={host} returncode={result.returncode} "
            f"command={remote_command!r}; detail={detail}"
        )
    return f"{result.stdout}\n{result.stderr}"


def _extract_protocol_names(rendered_config: str) -> list[str]:
    return re.findall(r"^protocol bgp ([a-z0-9_]+) \{$", rendered_config, flags=re.MULTILINE)


@pytest.mark.parametrize(
    ("rendered", "expected"),
    [
        (
            "protocol bgp ztix_as64590_node_abcde12345_v4_1_deadbeef0000 {\n",
            ["ztix_as64590_node_abcde12345_v4_1_deadbeef0000"],
        ),
        ("filter x {\n}\n", []),
    ],
)
def test_extract_protocol_names(rendered: str, expected: list[str]) -> None:
    assert _extract_protocol_names(rendered) == expected


class _RouteServerRuntimeConfig:
    def __init__(
        self,
        *,
        hosts: tuple[str, ...],
        ssh_user: str,
        ssh_port: int,
        ssh_private_key_path: str,
        ssh_connect_timeout_seconds: float,
        remote_config_dir: str,
        route_server_local_asn: int,
    ) -> None:
        self.hosts = hosts
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.ssh_private_key_path = ssh_private_key_path
        self.ssh_connect_timeout_seconds = ssh_connect_timeout_seconds
        self.remote_config_dir = remote_config_dir.rstrip("/")
        self.route_server_local_asn = route_server_local_asn


def _load_route_server_config(path: Path) -> _RouteServerRuntimeConfig:
    text = path.read_text()
    hosts_literal = _extract_required(
        text=text,
        pattern=r"^\s*hosts:\s*(\[[^\n]+\])\s*$",
        field="route_servers.hosts",
    )
    hosts_parsed = ast.literal_eval(hosts_literal)
    hosts = tuple(str(value) for value in hosts_parsed if str(value).strip())
    if not hosts:
        return _RouteServerRuntimeConfig(
            hosts=(),
            ssh_user="",
            ssh_port=22,
            ssh_private_key_path="",
            ssh_connect_timeout_seconds=10.0,
            remote_config_dir="/etc/bird/ztix-peers.d",
            route_server_local_asn=65000,
        )

    return _RouteServerRuntimeConfig(
        hosts=hosts,
        ssh_user=_extract_required(
            text=text,
            pattern=r"^\s*user:\s*([^\s#]+)\s*$",
            field="route_servers.ssh.user",
        ),
        ssh_port=int(
            _extract_required(
                text=text,
                pattern=r"^\s*port:\s*(\d+)\s*$",
                field="route_servers.ssh.port",
            )
        ),
        ssh_private_key_path=_extract_required(
            text=text,
            pattern=r"^\s*private_key_path:\s*([^\s#]+)\s*$",
            field="route_servers.ssh.private_key_path",
        ),
        ssh_connect_timeout_seconds=float(
            _extract_required(
                text=text,
                pattern=r"^\s*connect_timeout_seconds:\s*([0-9.]+)\s*$",
                field="route_servers.ssh.connect_timeout_seconds",
            )
        ),
        remote_config_dir=_extract_required(
            text=text,
            pattern=r"^\s*remote_config_dir:\s*([^\s#]+)\s*$",
            field="route_servers.remote_config_dir",
        ),
        route_server_local_asn=int(
            _extract_required(
                text=text,
                pattern=r"^\s*local_asn:\s*(\d+)\s*$",
                field="route_servers.local_asn",
            )
        ),
    )


def _extract_required(*, text: str, pattern: str, field: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing required runtime-config value: {field}")
    return match.group(1).strip()
