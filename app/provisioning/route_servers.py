"""Route-server desired-config rendering and SSH fanout."""

from __future__ import annotations

import hashlib
import ipaddress
import shlex
import subprocess
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.config import AppSettings

EndpointInterface = ipaddress.IPv4Interface | ipaddress.IPv6Interface
CommandRunner = Callable[[Sequence[str], str | None], subprocess.CompletedProcess[str]]


def _run_local_command(
    command: Sequence[str],
    stdin_data: str | None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        input=stdin_data,
        text=True,
        capture_output=True,
        check=False,
    )


class RouteServerSyncError(Exception):
    """Base exception for route-server desired-state sync failures."""

    error_code = "route_server_sync_error"


class RouteServerConfigInputError(RouteServerSyncError):
    """Raised when rendering inputs are not sufficient for deterministic config."""

    error_code = "route_server_config_input_error"


@dataclass(frozen=True, slots=True)
class RouteServerSyncResult:
    host: str
    remote_path: str
    config_sha256: str


class RouteServerSyncer(Protocol):
    def sync_desired_config(
        self,
        *,
        request_id: uuid.UUID,
        asn: int,
        zt_network_id: str,
        node_id: str,
        assigned_ips: list[str],
    ) -> list[RouteServerSyncResult]:
        """Write deterministic desired config to all configured route servers."""


class RouteServerSyncService:
    def __init__(
        self,
        *,
        route_server_hosts: tuple[str, ...],
        ssh_user: str,
        ssh_port: int,
        ssh_private_key_path: str,
        ssh_connect_timeout_seconds: float,
        ssh_strict_host_key: bool,
        ssh_known_hosts_file: str,
        remote_config_dir: str,
        route_server_local_asn: int,
        command_runner: CommandRunner = _run_local_command,
    ) -> None:
        self._route_server_hosts = route_server_hosts
        self._ssh_user = ssh_user
        self._ssh_port = ssh_port
        self._ssh_private_key_path = ssh_private_key_path
        self._ssh_connect_timeout_seconds = ssh_connect_timeout_seconds
        self._ssh_strict_host_key = ssh_strict_host_key
        self._ssh_known_hosts_file = ssh_known_hosts_file
        self._remote_config_dir = remote_config_dir.rstrip("/")
        self._route_server_local_asn = route_server_local_asn
        self._command_runner = command_runner

    def sync_desired_config(
        self,
        *,
        request_id: uuid.UUID,
        asn: int,
        zt_network_id: str,
        node_id: str,
        assigned_ips: list[str],
    ) -> list[RouteServerSyncResult]:
        if not self._route_server_hosts:
            return []

        rendered_config = render_bird_peer_config(
            request_id=request_id,
            asn=asn,
            zt_network_id=zt_network_id,
            node_id=node_id,
            assigned_ips=assigned_ips,
            route_server_local_asn=self._route_server_local_asn,
        )
        config_sha256 = hashlib.sha256(rendered_config.encode("utf-8")).hexdigest()
        remote_path = self._remote_path_for(request_id=request_id, asn=asn)
        mkdir_command = f"mkdir -p {shlex.quote(self._remote_config_dir)}"
        write_command = f"cat > {shlex.quote(remote_path)}"

        results: list[RouteServerSyncResult] = []
        failures: list[str] = []
        for host in self._route_server_hosts:
            try:
                self._run_ssh(host=host, remote_command=mkdir_command)
                self._run_ssh(
                    host=host,
                    remote_command=write_command,
                    stdin_data=rendered_config,
                )
                results.append(
                    RouteServerSyncResult(
                        host=host,
                        remote_path=remote_path,
                        config_sha256=config_sha256,
                    )
                )
            except RouteServerSyncError as exc:
                failures.append(f"{host}: {exc}")

        if failures:
            failure_list = "; ".join(failures)
            message = "route-server sync failed for one or more hosts: " f"{failure_list}"
            raise RouteServerSyncError(message)

        return results

    def _run_ssh(
        self,
        *,
        host: str,
        remote_command: str,
        stdin_data: str | None = None,
    ) -> None:
        command = self._build_ssh_command(host=host, remote_command=remote_command)
        try:
            result = self._command_runner(command, stdin_data)
        except OSError as exc:
            raise RouteServerSyncError(
                f"ssh invocation failed for host={host} command={remote_command!r}: {exc}"
            ) from exc

        if result.returncode == 0:
            return

        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr if stderr else stdout
        if detail:
            detail = detail[:240]
        else:
            detail = "no stderr/stdout output"
        message = (
            "ssh command failed for "
            f"host={host} returncode={result.returncode} command={remote_command!r}; "
            f"detail={detail}"
        )
        raise RouteServerSyncError(message)

    def _build_ssh_command(self, *, host: str, remote_command: str) -> list[str]:
        command = [
            "ssh",
            "-p",
            str(self._ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={int(self._ssh_connect_timeout_seconds)}",
        ]

        if self._ssh_private_key_path:
            command.extend(["-i", self._ssh_private_key_path])

        if self._ssh_strict_host_key:
            command.extend(["-o", "StrictHostKeyChecking=yes"])
            if self._ssh_known_hosts_file:
                command.extend(["-o", f"UserKnownHostsFile={self._ssh_known_hosts_file}"])
        else:
            command.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        target = f"{self._ssh_user}@{host}" if self._ssh_user else host
        command.extend([target, remote_command])
        return command

    def _remote_path_for(self, *, request_id: uuid.UUID, asn: int) -> str:
        return f"{self._remote_config_dir}/ztix_as{asn}_req_{request_id.hex}.conf"


def create_route_server_sync_service(
    settings: AppSettings,
    *,
    command_runner: CommandRunner = _run_local_command,
) -> RouteServerSyncService:
    return RouteServerSyncService(
        route_server_hosts=settings.route_server_hosts,
        ssh_user=settings.route_server_ssh_user,
        ssh_port=settings.route_server_ssh_port,
        ssh_private_key_path=settings.route_server_ssh_private_key_path,
        ssh_connect_timeout_seconds=settings.route_server_ssh_connect_timeout_seconds,
        ssh_strict_host_key=settings.route_server_ssh_strict_host_key,
        ssh_known_hosts_file=settings.route_server_ssh_known_hosts_file,
        remote_config_dir=settings.route_server_remote_config_dir,
        route_server_local_asn=settings.route_server_local_asn,
        command_runner=command_runner,
    )


def render_bird_peer_config(
    *,
    request_id: uuid.UUID,
    asn: int,
    zt_network_id: str,
    node_id: str,
    assigned_ips: list[str],
    route_server_local_asn: int,
) -> str:
    endpoints = _normalize_assigned_endpoints(assigned_ips)
    if not endpoints:
        raise RouteServerConfigInputError(
            "at least one assigned IP is required to generate route-server peer config"
        )

    filter_v4 = _sanitize_identifier(f"ztix_roa_guard_v4_as{asn}")
    filter_v6 = _sanitize_identifier(f"ztix_roa_guard_v6_as{asn}")

    lines = [
        f"# Managed by zt-ix for request_id={request_id}",
        f"# ASN={asn} node_id={node_id} zt_network_id={zt_network_id}",
        "# RPKI/ROA tables ztix_roa_v4 and ztix_roa_v6 must be populated by router ops.",
        "",
        f"filter {filter_v4} {{",
        "  if roa_check(ztix_roa_v4, net, bgp_path.last) = ROA_INVALID then reject;",
        "  accept;",
        "}",
        "",
        f"filter {filter_v6} {{",
        "  if roa_check(ztix_roa_v6, net, bgp_path.last) = ROA_INVALID then reject;",
        "  accept;",
        "}",
        "",
    ]

    request_token = request_id.hex[:12]
    for index, endpoint in enumerate(endpoints, start=1):
        family = "v4" if endpoint.version == 4 else "v6"
        filter_name = filter_v4 if endpoint.version == 4 else filter_v6
        address_family = "ipv4" if endpoint.version == 4 else "ipv6"
        protocol_name = _sanitize_identifier(
            f"ztix_as{asn}_node_{node_id}_{family}_{index}_{request_token}"
        )
        lines.extend(
            [
                f"protocol bgp {protocol_name} {{",
                f'  description "zt-ix as{asn} request {request_id} node {node_id}";',
                f"  local as {route_server_local_asn};",
                f"  neighbor {endpoint.ip.compressed} as {asn};",
                f"  {address_family} {{",
                f"    import filter {filter_name};",
                "    export all;",
                "  };",
                "}",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def _normalize_assigned_endpoints(assigned_ips: list[str]) -> list[EndpointInterface]:
    deduped: dict[str, EndpointInterface] = {}

    for raw_value in assigned_ips:
        candidate = raw_value.strip()
        if not candidate:
            continue
        try:
            interface = ipaddress.ip_interface(candidate)
        except ValueError as exc:
            raise RouteServerConfigInputError(f"invalid assigned IP value {candidate!r}") from exc
        deduped[interface.ip.compressed] = interface

    endpoints = list(deduped.values())
    endpoints.sort(key=lambda value: (value.version, int(value.ip)))
    return endpoints


def _sanitize_identifier(value: str) -> str:
    normalized = "".join(char if char.isalnum() else "_" for char in value.lower())
    normalized = normalized.strip("_")
    if not normalized:
        return "ztix_identifier"
    return normalized
