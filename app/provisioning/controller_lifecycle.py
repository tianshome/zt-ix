"""Lifecycle operations for owned self-hosted ZeroTier controller mode."""

from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import AppSettings
from app.db.models import ZtNetwork
from app.provisioning.controller_auth import (
    read_controller_auth_token_file,
    resolve_controller_auth_token,
)
from app.repositories.audit_events import AuditEventRepository

HTTPClientFactory = Callable[..., httpx.Client]
REQUIRED_CONTROLLER_STATE_ARTIFACTS = (
    "controller.d",
    "identity.public",
    "identity.secret",
    "authtoken.secret",
)
LOWER_HEX_CHARS = frozenset("0123456789abcdef")
LIFECYCLE_TARGET_TYPE = "controller_lifecycle"
LIFECYCLE_TARGET_ID = "self_hosted_controller"


class ControllerLifecycleError(Exception):
    """Base exception type for deterministic lifecycle failure handling."""

    error_code = "controller_lifecycle_error"

    def __init__(
        self,
        message: str,
        *,
        remediation: str,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.remediation = remediation
        self.status_code = status_code


class ControllerReadinessError(ControllerLifecycleError):
    error_code = "controller_readiness_error"


class ControllerNetworkReconciliationError(ControllerLifecycleError):
    error_code = "controller_network_reconciliation_error"


class ControllerLifecycleGateError(ControllerLifecycleError):
    error_code = "controller_lifecycle_gate_error"


class ControllerTokenReloadError(ControllerLifecycleError):
    error_code = "controller_token_reload_error"


class ControllerBackupError(ControllerLifecycleError):
    error_code = "controller_backup_error"


class ControllerRestoreError(ControllerLifecycleError):
    error_code = "controller_restore_error"


@dataclass(frozen=True, slots=True)
class ControllerReadinessResult:
    status_probe_code: int
    controller_probe_code: int
    controller_id: str | None


@dataclass(frozen=True, slots=True)
class ControllerRequiredNetworkDerivationResult:
    controller_prefix: str
    configured_full_network_ids: tuple[str, ...]
    configured_network_suffixes: tuple[str, ...]
    expanded_suffix_network_ids: tuple[str, ...]
    required_network_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControllerNetworkReconcileResult:
    existing_network_ids: tuple[str, ...]
    created_network_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControllerPreflightResult:
    readiness: ControllerReadinessResult
    network_reconcile: ControllerNetworkReconcileResult


@dataclass(frozen=True, slots=True)
class ControllerBackupResult:
    backup_path: str
    copied_artifacts: tuple[str, ...]
    pruned_backup_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControllerRestoreResult:
    restored_from: str
    restored_artifacts: tuple[str, ...]


class SelfHostedControllerLifecycleManager:
    """Controller lifecycle operations for readiness, reconciliation, and state workflows."""

    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        required_network_suffixes: tuple[str, ...],
        required_network_ids: tuple[str, ...],
        backup_dir: str,
        backup_retention_count: int,
        controller_state_dir: str,
        auth_token_file: str = "",
        timeout_seconds: float = 10.0,
        http_client_factory: HTTPClientFactory = httpx.Client,
    ) -> None:
        normalized_base_url = base_url.strip().rstrip("/")
        if not normalized_base_url:
            raise ValueError("ZT_CONTROLLER_BASE_URL is required")

        normalized_token = auth_token.strip()
        if not normalized_token:
            raise ValueError("ZT_CONTROLLER_AUTH_TOKEN is required for lifecycle operations")

        normalized_suffixes = tuple(
            suffix.strip() for suffix in required_network_suffixes if suffix.strip()
        )
        normalized_networks = tuple(
            network_id.strip() for network_id in required_network_ids if network_id.strip()
        )

        self._controller_base_url = normalized_base_url
        self._service_base_url = normalized_base_url.removesuffix("/controller")
        self._auth_token = normalized_token
        self._required_network_suffixes = normalized_suffixes
        self._required_network_ids = normalized_networks
        self._backup_dir = Path(backup_dir).expanduser()
        self._backup_retention_count = max(1, int(backup_retention_count))
        self._controller_state_dir = Path(controller_state_dir).expanduser()
        self._auth_token_file = auth_token_file.strip()
        self._timeout_seconds = timeout_seconds
        self._http_client_factory = http_client_factory

    @property
    def auth_token_file(self) -> str:
        return self._auth_token_file

    @property
    def required_network_ids(self) -> tuple[str, ...]:
        return self._required_network_ids

    @property
    def required_network_suffixes(self) -> tuple[str, ...]:
        return self._required_network_suffixes

    @property
    def backup_retention_count(self) -> int:
        return self._backup_retention_count

    def probe_readiness(self) -> ControllerReadinessResult:
        readiness_remediation = (
            "verify controller runtime health and that API port 9993 is reachable "
            "from this service"
        )
        status_response = self._request(
            base_url=self._service_base_url,
            method="GET",
            path="/status",
            error_cls=ControllerReadinessError,
            remediation=readiness_remediation,
        )
        self._raise_for_status(
            status_response,
            error_cls=ControllerReadinessError,
            default_message="controller status probe failed",
            remediation=readiness_remediation,
        )

        controller_response = self._request(
            base_url=self._service_base_url,
            method="GET",
            path="/controller",
            error_cls=ControllerReadinessError,
            remediation=(
                "verify controller API token has management privileges and "
                "allowManagementFrom includes this service"
            ),
        )
        self._raise_for_status(
            controller_response,
            error_cls=ControllerReadinessError,
            default_message="controller metadata probe failed",
            remediation=(
                "verify controller API token has management privileges and "
                "allowManagementFrom includes this service"
            ),
        )

        controller_payload = _parse_json_object(
            controller_response,
            error_cls=ControllerReadinessError,
            message_prefix="controller metadata response was not a JSON object",
            remediation="verify controller API compatibility and token scope",
        )
        controller_id = _extract_non_empty_str(status_response.json(), "address")
        return ControllerReadinessResult(
            status_probe_code=status_response.status_code,
            controller_probe_code=controller_response.status_code,
            controller_id=controller_id,
        )

    def derive_required_networks(
        self,
        *,
        controller_id: str | None,
    ) -> ControllerRequiredNetworkDerivationResult:
        derivation_remediation = (
            "set zerotier.self_hosted_controller.lifecycle.required_network_suffixes "
            "to unique 6-char lowercase hex values"
        )
        controller_prefix = _derive_controller_prefix(controller_id)
        configured_full_ids = self._normalize_required_network_ids()
        configured_suffixes = self._normalize_required_network_suffixes(
            remediation=derivation_remediation,
        )

        expanded_from_suffixes = tuple(
            f"{controller_prefix}{suffix}" for suffix in configured_suffixes
        )
        duplicate_full_ids = sorted(
            set(configured_full_ids).intersection(expanded_from_suffixes)
        )
        if duplicate_full_ids:
            duplicates = ", ".join(duplicate_full_ids)
            raise ControllerNetworkReconciliationError(
                (
                    "required network IDs are repeated across suffix and legacy full-ID "
                    f"configuration: {duplicates}"
                ),
                remediation=(
                    "remove duplicated full IDs from legacy required_network_ids when "
                    "suffix-based configuration is enabled"
                ),
            )

        merged_required_ids = configured_full_ids + expanded_from_suffixes
        return ControllerRequiredNetworkDerivationResult(
            controller_prefix=controller_prefix,
            configured_full_network_ids=configured_full_ids,
            configured_network_suffixes=configured_suffixes,
            expanded_suffix_network_ids=expanded_from_suffixes,
            required_network_ids=merged_required_ids,
        )

    def reconcile_required_networks(
        self,
        *,
        required_network_ids: tuple[str, ...],
    ) -> ControllerNetworkReconcileResult:
        reconcile_remediation = (
            "verify controller network API access and configured "
            "required network suffixes/full IDs"
        )
        existing: list[str] = []
        created: list[str] = []
        for network_id in required_network_ids:
            self._validate_network_id(network_id)
            lookup_response = self._request(
                base_url=self._controller_base_url,
                method="GET",
                path=f"/network/{network_id}",
                error_cls=ControllerNetworkReconciliationError,
                remediation=reconcile_remediation,
            )
            if lookup_response.status_code == 404:
                self._create_required_network(network_id)
                created.append(network_id)
                continue

            self._raise_for_status(
                lookup_response,
                error_cls=ControllerNetworkReconciliationError,
                default_message=f"failed to validate required controller network {network_id}",
                remediation=reconcile_remediation,
            )
            existing.append(network_id)

        return ControllerNetworkReconcileResult(
            existing_network_ids=tuple(existing),
            created_network_ids=tuple(created),
        )

    def reload_auth_token(self, *, token_file: str | None = None) -> str:
        source = (token_file or self._auth_token_file).strip()
        if not source:
            raise ControllerTokenReloadError(
                "controller token reload source is not configured",
                remediation="set ZT_CONTROLLER_AUTH_TOKEN_FILE or pass --token-file",
            )

        try:
            token = read_controller_auth_token_file(source)
        except ValueError as exc:
            raise ControllerTokenReloadError(
                str(exc),
                remediation="ensure controller auth token file exists and contains a token",
            ) from exc

        self._auth_token = token
        return token

    def backup_state(self) -> ControllerBackupResult:
        state_dir = self._controller_state_dir
        if not state_dir.is_dir():
            raise ControllerBackupError(
                f"controller state directory does not exist: {state_dir}",
                remediation="set ZT_CONTROLLER_STATE_DIR to the mounted controller state path",
            )

        backup_root = self._backup_dir
        try:
            backup_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ControllerBackupError(
                f"failed to create backup directory {backup_root}: {exc}",
                remediation="verify write permissions for ZT_CONTROLLER_BACKUP_DIR",
            ) from exc

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_root / f"zt_controller_{timestamp}_{uuid.uuid4().hex[:8]}"
        copied_artifacts: list[str] = []

        try:
            backup_path.mkdir(parents=True, exist_ok=False)
            for artifact in REQUIRED_CONTROLLER_STATE_ARTIFACTS:
                source_path = state_dir / artifact
                if not source_path.exists():
                    raise ControllerBackupError(
                        f"required controller state artifact is missing: {source_path}",
                        remediation=(
                            "ensure controller state has identity/authtoken/controller.d "
                            "before running backup"
                        ),
                    )

                destination_path = backup_path / artifact
                if source_path.is_dir():
                    shutil.copytree(source_path, destination_path)
                else:
                    shutil.copy2(source_path, destination_path)
                copied_artifacts.append(artifact)

            manifest = {
                "created_at": datetime.now(UTC).isoformat(),
                "source_state_dir": str(state_dir),
                "artifacts": copied_artifacts,
            }
            (backup_path / "manifest.json").write_text(
                json.dumps(manifest, sort_keys=True, indent=2),
                encoding="utf-8",
            )
        except ControllerBackupError:
            shutil.rmtree(backup_path, ignore_errors=True)
            raise
        except OSError as exc:
            shutil.rmtree(backup_path, ignore_errors=True)
            raise ControllerBackupError(
                f"failed to materialize controller backup at {backup_path}: {exc}",
                remediation="verify backup directory permissions and available disk space",
            ) from exc

        try:
            pruned_backup_paths = self._prune_backups(backup_root)
        except OSError as exc:
            raise ControllerBackupError(
                f"failed to prune old controller backups in {backup_root}: {exc}",
                remediation="verify backup directory permissions and retention settings",
            ) from exc
        return ControllerBackupResult(
            backup_path=str(backup_path),
            copied_artifacts=tuple(copied_artifacts),
            pruned_backup_paths=tuple(pruned_backup_paths),
        )

    def restore_state(self, *, backup_path: str) -> ControllerRestoreResult:
        source_backup = Path(backup_path).expanduser()
        if not source_backup.is_dir():
            raise ControllerRestoreError(
                f"backup path does not exist: {source_backup}",
                remediation="pass a valid backup directory created by controller backup workflow",
            )

        state_dir = self._controller_state_dir
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ControllerRestoreError(
                f"failed to create state directory {state_dir}: {exc}",
                remediation="verify write permissions for ZT_CONTROLLER_STATE_DIR",
            ) from exc

        restored_artifacts: list[str] = []
        try:
            for artifact in REQUIRED_CONTROLLER_STATE_ARTIFACTS:
                source_path = source_backup / artifact
                if not source_path.exists():
                    raise ControllerRestoreError(
                        f"backup artifact is missing: {source_path}",
                        remediation="validate backup completeness before restore",
                    )

                destination_path = state_dir / artifact
                if destination_path.exists():
                    if destination_path.is_dir():
                        shutil.rmtree(destination_path)
                    else:
                        destination_path.unlink()

                if source_path.is_dir():
                    shutil.copytree(source_path, destination_path)
                else:
                    shutil.copy2(source_path, destination_path)
                restored_artifacts.append(artifact)
        except ControllerRestoreError:
            raise
        except OSError as exc:
            raise ControllerRestoreError(
                f"failed to restore controller artifact into {state_dir}: {exc}",
                remediation="ensure controller state directory is writable",
            ) from exc

        return ControllerRestoreResult(
            restored_from=str(source_backup),
            restored_artifacts=tuple(restored_artifacts),
        )

    def _create_required_network(self, network_id: str) -> None:
        creation_attempts: tuple[tuple[str, str, dict[str, str]], ...] = (
            ("POST", f"/network/{network_id}", {}),
            ("PUT", f"/network/{network_id}", {}),
            ("POST", "/network", {"id": network_id}),
        )
        for method, path, payload in creation_attempts:
            response = self._request(
                base_url=self._controller_base_url,
                method=method,
                path=path,
                json_body=payload,
                error_cls=ControllerNetworkReconciliationError,
                remediation=(
                    "verify controller API supports network creation and the "
                    "configured network IDs are valid"
                ),
            )
            if response.status_code in {404, 405}:
                continue
            self._raise_for_status(
                response,
                error_cls=ControllerNetworkReconciliationError,
                default_message=f"failed to create required controller network {network_id}",
                remediation=(
                    "verify controller API supports network creation and the "
                    "configured network IDs are valid"
                ),
            )
            return

        raise ControllerNetworkReconciliationError(
            (
                "controller network creation endpoint was not available for "
                f"required network {network_id}"
            ),
            remediation=(
                "verify controller API compatibility and network creation permissions "
                "for this deployment"
            ),
        )

    def _prune_backups(self, backup_root: Path) -> list[str]:
        backup_dirs = sorted(
            [
                candidate
                for candidate in backup_root.iterdir()
                if candidate.is_dir() and candidate.name.startswith("zt_controller_")
            ],
            key=lambda candidate: candidate.name,
        )
        keep_count = self._backup_retention_count
        if len(backup_dirs) <= keep_count:
            return []

        prune_targets = backup_dirs[: len(backup_dirs) - keep_count]
        pruned: list[str] = []
        for target in prune_targets:
            shutil.rmtree(target, ignore_errors=False)
            pruned.append(str(target))
        return pruned

    def _request(
        self,
        *,
        base_url: str,
        method: str,
        path: str,
        error_cls: type[ControllerLifecycleError],
        remediation: str,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        with self._http_client_factory(
            base_url=base_url,
            headers={"X-ZT1-Auth": self._auth_token},
            timeout=self._timeout_seconds,
        ) as client:
            try:
                return client.request(method, path, json=json_body)
            except httpx.HTTPError as exc:
                raise error_cls(
                    f"controller request failed: {exc}",
                    remediation=remediation,
                ) from exc

    def _raise_for_status(
        self,
        response: httpx.Response,
        *,
        error_cls: type[ControllerLifecycleError],
        default_message: str,
        remediation: str,
    ) -> None:
        status_code = response.status_code
        if status_code < 400:
            return
        if status_code in {401, 403}:
            raise error_cls(
                f"controller authentication failed with status={status_code}",
                remediation=(
                    "reload controller auth token and verify controller management "
                    "API auth settings"
                ),
                status_code=status_code,
            )

        body = response.text.strip()
        detail = f"{default_message}; status={status_code}"
        if body:
            detail = f"{detail}; body={body[:240]}"
        raise error_cls(
            detail,
            remediation=remediation,
            status_code=status_code,
        )

    def _validate_network_id(self, network_id: str) -> None:
        if len(network_id) != 16 or not _is_lower_hex(network_id):
            raise ControllerNetworkReconciliationError(
                f"invalid controller network id in required set: {network_id!r}",
                remediation="set ZT_CONTROLLER_REQUIRED_NETWORK_IDS to 16-char lowercase hex IDs",
            )

    def _normalize_required_network_ids(self) -> tuple[str, ...]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_network_id in self._required_network_ids:
            network_id = raw_network_id.strip()
            self._validate_network_id(network_id)
            if network_id in seen:
                continue
            seen.add(network_id)
            normalized.append(network_id)
        return tuple(normalized)

    def _normalize_required_network_suffixes(self, *, remediation: str) -> tuple[str, ...]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_suffix in self._required_network_suffixes:
            suffix = raw_suffix.strip()
            if len(suffix) != 6 or not _is_lower_hex(suffix):
                raise ControllerNetworkReconciliationError(
                    f"invalid controller network suffix in required set: {raw_suffix!r}",
                    remediation=remediation,
                )
            if suffix in seen:
                raise ControllerNetworkReconciliationError(
                    f"duplicate controller network suffix in required set: {suffix!r}",
                    remediation=remediation,
                )
            seen.add(suffix)
            normalized.append(suffix)
        return tuple(normalized)


def create_controller_lifecycle_manager(
    settings: AppSettings,
    *,
    http_client_factory: HTTPClientFactory = httpx.Client,
) -> SelfHostedControllerLifecycleManager:
    token = resolve_controller_auth_token(settings)
    return SelfHostedControllerLifecycleManager(
        base_url=settings.zt_controller_base_url,
        auth_token=token,
        required_network_suffixes=settings.zt_controller_required_network_suffixes,
        required_network_ids=settings.zt_controller_required_network_ids,
        backup_dir=settings.zt_controller_backup_dir,
        backup_retention_count=settings.zt_controller_backup_retention_count,
        controller_state_dir=settings.zt_controller_state_dir,
        auth_token_file=settings.zt_controller_auth_token_file,
        http_client_factory=http_client_factory,
    )


def run_controller_lifecycle_preflight(
    *,
    manager: SelfHostedControllerLifecycleManager,
    db_session: Session,
    strict_fail_closed: bool,
    trigger: str,
    actor_user_id: uuid.UUID | None = None,
    request_id: uuid.UUID | None = None,
) -> ControllerPreflightResult | None:
    audit_repo = AuditEventRepository(db_session)
    base_metadata = {
        "trigger": trigger,
        "configured_required_network_ids": list(manager.required_network_ids),
        "configured_required_network_suffixes": list(manager.required_network_suffixes),
    }
    if request_id is not None:
        base_metadata["request_id"] = str(request_id)

    try:
        readiness = manager.probe_readiness()
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.readiness.failed",
            actor_user_id=actor_user_id,
            metadata={
                **base_metadata,
                **_error_metadata(exc),
            },
        )
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.preflight.failed",
            actor_user_id=actor_user_id,
            metadata={
                **base_metadata,
                **_error_metadata(exc),
                "failed_stage": "readiness",
            },
        )
        db_session.commit()
        if strict_fail_closed:
            raise ControllerLifecycleGateError(
                f"controller lifecycle readiness gate failed: {exc}",
                remediation=exc.remediation,
            ) from exc
        return None

    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.readiness.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            **base_metadata,
            "status_probe_code": readiness.status_probe_code,
            "controller_probe_code": readiness.controller_probe_code,
            "controller_id": readiness.controller_id,
        },
    )

    try:
        network_derivation = manager.derive_required_networks(
            controller_id=readiness.controller_id
        )
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.required_network_derivation.failed",
            actor_user_id=actor_user_id,
            metadata={
                **base_metadata,
                "controller_id": readiness.controller_id,
                **_error_metadata(exc),
            },
        )
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.preflight.failed",
            actor_user_id=actor_user_id,
            metadata={
                **base_metadata,
                "controller_id": readiness.controller_id,
                **_error_metadata(exc),
                "failed_stage": "required_network_derivation",
            },
        )
        db_session.commit()
        if strict_fail_closed:
            raise ControllerLifecycleGateError(
                f"controller lifecycle required-network derivation failed: {exc}",
                remediation=exc.remediation,
            ) from exc
        return None

    derivation_metadata = {
        "controller_id": readiness.controller_id,
        "controller_prefix": network_derivation.controller_prefix,
        "required_network_ids": list(network_derivation.required_network_ids),
        "expanded_suffix_network_ids": list(network_derivation.expanded_suffix_network_ids),
    }
    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.required_network_derivation.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            **base_metadata,
            **derivation_metadata,
            "configured_required_network_ids": list(
                network_derivation.configured_full_network_ids
            ),
            "configured_required_network_suffixes": list(
                network_derivation.configured_network_suffixes
            ),
        },
    )
    preflight_metadata = {**base_metadata, **derivation_metadata}

    try:
        network_reconcile = manager.reconcile_required_networks(
            required_network_ids=network_derivation.required_network_ids
        )
        reconciled_network_ids = (
            network_reconcile.existing_network_ids + network_reconcile.created_network_ids
        )
        _sync_reconciled_network_ids_to_db(
            db_session=db_session,
            reconciled_network_ids=reconciled_network_ids,
        )
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.network_reconciliation.failed",
            actor_user_id=actor_user_id,
            metadata={
                **preflight_metadata,
                **_error_metadata(exc),
            },
        )
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.preflight.failed",
            actor_user_id=actor_user_id,
            metadata={
                **preflight_metadata,
                **_error_metadata(exc),
                "failed_stage": "network_reconciliation",
            },
        )
        db_session.commit()
        if strict_fail_closed:
            raise ControllerLifecycleGateError(
                f"controller lifecycle network reconciliation failed: {exc}",
                remediation=exc.remediation,
            ) from exc
        return None

    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.network_reconciliation.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            **preflight_metadata,
            "existing_network_ids": list(network_reconcile.existing_network_ids),
            "created_network_ids": list(network_reconcile.created_network_ids),
            "existing_count": len(network_reconcile.existing_network_ids),
            "created_count": len(network_reconcile.created_network_ids),
        },
    )
    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.preflight.succeeded",
        actor_user_id=actor_user_id,
        metadata=preflight_metadata,
    )
    db_session.commit()
    return ControllerPreflightResult(
        readiness=readiness,
        network_reconcile=network_reconcile,
    )


def run_controller_token_reload(
    *,
    manager: SelfHostedControllerLifecycleManager,
    db_session: Session,
    trigger: str,
    actor_user_id: uuid.UUID | None = None,
    token_file: str | None = None,
) -> str:
    audit_repo = AuditEventRepository(db_session)
    source = (token_file or manager.auth_token_file).strip()
    if not source:
        error = ControllerTokenReloadError(
            "controller token reload source is not configured",
            remediation="set ZT_CONTROLLER_AUTH_TOKEN_FILE or pass --token-file",
        )
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.token_reload.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                **_error_metadata(error),
            },
        )
        db_session.commit()
        raise error

    try:
        token = manager.reload_auth_token(token_file=source)
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.token_reload.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                "token_file": source,
                **_error_metadata(exc),
            },
        )
        db_session.commit()
        raise
    try:
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger=f"{trigger}:token_reload",
            actor_user_id=actor_user_id,
        )
    except ControllerLifecycleGateError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.token_reload.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                "token_file": source,
                **_error_metadata(exc),
            },
        )
        db_session.commit()
        raise ControllerTokenReloadError(
            f"controller token reload validation failed: {exc}",
            remediation=exc.remediation,
        ) from exc

    token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.token_reload.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            "trigger": trigger,
            "token_file": source,
            "token_sha256_prefix": token_fingerprint,
        },
    )
    db_session.commit()
    return token


def run_controller_backup(
    *,
    manager: SelfHostedControllerLifecycleManager,
    db_session: Session,
    trigger: str,
    actor_user_id: uuid.UUID | None = None,
) -> ControllerBackupResult:
    audit_repo = AuditEventRepository(db_session)
    try:
        result = manager.backup_state()
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.backup.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                **_error_metadata(exc),
            },
        )
        db_session.commit()
        raise

    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.backup.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            "trigger": trigger,
            "backup_path": result.backup_path,
            "copied_artifacts": list(result.copied_artifacts),
            "pruned_backup_paths": list(result.pruned_backup_paths),
            "retention_count": manager.backup_retention_count,
        },
    )
    db_session.commit()
    return result


def run_controller_restore(
    *,
    manager: SelfHostedControllerLifecycleManager,
    db_session: Session,
    trigger: str,
    backup_path: str,
    actor_user_id: uuid.UUID | None = None,
) -> ControllerRestoreResult:
    audit_repo = AuditEventRepository(db_session)
    try:
        result = manager.restore_state(backup_path=backup_path)
    except ControllerLifecycleError as exc:
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.restore.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                "backup_path": backup_path,
                **_error_metadata(exc),
            },
        )
        db_session.commit()
        raise

    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.restore.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            "trigger": trigger,
            "backup_path": backup_path,
            "restored_artifacts": list(result.restored_artifacts),
        },
    )
    db_session.commit()
    return result


def run_controller_restore_validation_drill(
    *,
    manager: SelfHostedControllerLifecycleManager,
    db_session: Session,
    trigger: str,
    backup_path: str,
    actor_user_id: uuid.UUID | None = None,
) -> ControllerRestoreResult:
    restore_result = run_controller_restore(
        manager=manager,
        db_session=db_session,
        trigger=f"{trigger}:restore",
        backup_path=backup_path,
        actor_user_id=actor_user_id,
    )

    try:
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger=f"{trigger}:restore_validation",
            actor_user_id=actor_user_id,
        )
    except ControllerLifecycleGateError as exc:
        audit_repo = AuditEventRepository(db_session)
        _audit_lifecycle_event(
            audit_repo=audit_repo,
            action="controller_lifecycle.restore_validation.failed",
            actor_user_id=actor_user_id,
            metadata={
                "trigger": trigger,
                "backup_path": backup_path,
                **_error_metadata(exc),
            },
        )
        db_session.commit()
        raise ControllerRestoreError(
            f"controller restore validation drill failed: {exc}",
            remediation=exc.remediation,
        ) from exc

    audit_repo = AuditEventRepository(db_session)
    _audit_lifecycle_event(
        audit_repo=audit_repo,
        action="controller_lifecycle.restore_validation.succeeded",
        actor_user_id=actor_user_id,
        metadata={
            "trigger": trigger,
            "backup_path": backup_path,
            "restored_artifacts": list(restore_result.restored_artifacts),
        },
    )
    db_session.commit()
    return restore_result


def _audit_lifecycle_event(
    *,
    audit_repo: AuditEventRepository,
    action: str,
    metadata: dict[str, Any],
    actor_user_id: uuid.UUID | None,
) -> None:
    audit_repo.create_event(
        action=action,
        target_type=LIFECYCLE_TARGET_TYPE,
        target_id=LIFECYCLE_TARGET_ID,
        actor_user_id=actor_user_id,
        metadata=metadata,
    )


def _sync_reconciled_network_ids_to_db(
    *,
    db_session: Session,
    reconciled_network_ids: tuple[str, ...],
) -> None:
    stale_remediation = (
        "remove stale network references (join_request/zt_membership) or align "
        "required network configuration before re-running preflight"
    )
    sync_remediation = (
        "verify database availability and zt_network row integrity before "
        "re-running preflight"
    )
    reconcile_set = set(reconciled_network_ids)
    if len(reconcile_set) != len(reconciled_network_ids):
        duplicates = sorted(
            network_id
            for network_id in reconcile_set
            if reconciled_network_ids.count(network_id) > 1
        )
        raise ControllerNetworkReconciliationError(
            (
                "duplicate network ids detected while syncing lifecycle reconciliation "
                f"results to SQL DB: {', '.join(duplicates)}"
            ),
            remediation=(
                "verify required_network_ids/required_network_suffixes expansion produces "
                "a unique network id set"
            ),
        )

    try:
        with db_session.begin_nested():
            db_network_rows = list(
                db_session.execute(select(ZtNetwork)).scalars()
            )
            db_rows_by_id = {row.id: row for row in db_network_rows}

            for network_id in reconciled_network_ids:
                existing_row = db_rows_by_id.pop(network_id, None)
                if existing_row is None:
                    db_session.add(
                        ZtNetwork(
                            id=network_id,
                            name=f"ZT Network {network_id}",
                            is_active=True,
                        )
                    )
                    continue
                existing_row.is_active = True

            for stale_row in db_rows_by_id.values():
                db_session.delete(stale_row)

            db_session.flush()
    except IntegrityError as exc:
        raise ControllerNetworkReconciliationError(
            (
                "failed to synchronize controller network reconciliation result to SQL DB; "
                "stale network rows are still referenced"
            ),
            remediation=stale_remediation,
        ) from exc
    except SQLAlchemyError as exc:
        raise ControllerNetworkReconciliationError(
            "failed to synchronize controller network reconciliation result to SQL DB",
            remediation=sync_remediation,
        ) from exc


def _error_metadata(exc: ControllerLifecycleError) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "error_code": exc.error_code,
        "error": str(exc),
        "remediation": exc.remediation,
    }
    if exc.status_code is not None:
        metadata["status_code"] = exc.status_code
    return metadata


def _parse_json_object(
    response: httpx.Response,
    *,
    error_cls: type[ControllerLifecycleError],
    message_prefix: str,
    remediation: str,
) -> dict[str, Any]:
    try:
        parsed = response.json()
    except ValueError as exc:
        raise error_cls(
            f"{message_prefix}; status={response.status_code}",
            remediation=remediation,
            status_code=response.status_code,
        ) from exc

    if not isinstance(parsed, dict):
        raise error_cls(
            f"{message_prefix}; status={response.status_code}",
            remediation=remediation,
            status_code=response.status_code,
        )
    return parsed


def _extract_non_empty_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _derive_controller_prefix(controller_id: str | None) -> str:
    if controller_id is None:
        raise ControllerNetworkReconciliationError(
            "controller metadata did not include a usable id for prefix derivation",
            remediation=(
                "verify GET /controller returns id and controller API compatibility "
                "for this deployment"
            ),
        )
    normalized_id = controller_id.strip().lower()
    if len(normalized_id) < 10:
        raise ControllerNetworkReconciliationError(
            f"controller id is too short for prefix derivation: {controller_id!r}",
            remediation="verify controller API returns a standard 10-char node id",
        )
    prefix = normalized_id[:10]
    if not _is_lower_hex(prefix):
        raise ControllerNetworkReconciliationError(
            f"controller prefix derived from id is not lowercase hex: {prefix!r}",
            remediation="verify controller API id format and runtime compatibility",
        )
    return prefix


def _is_lower_hex(value: str) -> bool:
    return bool(value) and all(ch in LOWER_HEX_CHARS for ch in value)
