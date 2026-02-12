from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent, ZtNetwork
from app.provisioning.controller_lifecycle import (
    ControllerLifecycleGateError,
    ControllerRestoreError,
    ControllerTokenReloadError,
    SelfHostedControllerLifecycleManager,
    run_controller_backup,
    run_controller_lifecycle_preflight,
    run_controller_restore_validation_drill,
    run_controller_token_reload,
)

CONTROLLER_ID = "a1b2c3d4e5"


def test_preflight_succeeds_and_writes_audit_events(db_session: Session, tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected path {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
    )
    result = run_controller_lifecycle_preflight(
        manager=manager,
        db_session=db_session,
        strict_fail_closed=True,
        trigger="test_preflight",
    )

    assert result is not None
    assert result.readiness.controller_id == CONTROLLER_ID
    assert result.network_reconcile.created_network_ids == ()

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.readiness.succeeded" in actions
    assert "controller_lifecycle.required_network_derivation.succeeded" in actions
    assert "controller_lifecycle.network_reconciliation.succeeded" in actions
    assert "controller_lifecycle.preflight.succeeded" in actions


def test_preflight_readiness_failure_blocks_when_strict(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=401, json={"error": "unauthorized"})
        raise AssertionError(f"unexpected path {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=("abcdef0123456789",),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_preflight_fail",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.readiness.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_network_reconciliation_creates_missing_required_network(
    db_session: Session,
    tmp_path: Path,
) -> None:
    missing = "0123456789abcdef"
    existing = "abcdef0123456789"
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{existing}":
            return httpx.Response(status_code=200, json={"id": existing})
        if request.url.path == f"/controller/network/{missing}" and request.method == "GET":
            return httpx.Response(status_code=404, json={"error": "missing"})
        if request.url.path == f"/controller/network/{missing}" and request.method == "POST":
            return httpx.Response(status_code=200, json={"id": missing})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(existing, missing),
    )
    result = run_controller_lifecycle_preflight(
        manager=manager,
        db_session=db_session,
        strict_fail_closed=True,
        trigger="test_network_reconcile",
    )

    assert result is not None
    assert result.network_reconcile.existing_network_ids == (existing,)
    assert result.network_reconcile.created_network_ids == (missing,)
    assert ("POST", f"/controller/network/{missing}") in seen


def test_preflight_syncs_zt_network_rows_to_reconciled_ids(
    db_session: Session,
    tmp_path: Path,
) -> None:
    stale = "1111111111111111"
    existing = "abcdef0123456789"
    missing = "0123456789abcdef"
    db_session.add_all(
        [
            ZtNetwork(id=stale, name="Stale", is_active=True),
            ZtNetwork(id=existing, name="Existing", is_active=False),
        ]
    )
    db_session.commit()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{existing}":
            return httpx.Response(status_code=200, json={"id": existing})
        if request.url.path == f"/controller/network/{missing}" and request.method == "GET":
            return httpx.Response(status_code=404, json={"error": "missing"})
        if request.url.path == f"/controller/network/{missing}" and request.method == "POST":
            return httpx.Response(status_code=200, json={"id": missing})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(existing, missing),
    )
    result = run_controller_lifecycle_preflight(
        manager=manager,
        db_session=db_session,
        strict_fail_closed=True,
        trigger="test_network_db_sync",
    )

    assert result is not None
    assert result.network_reconcile.existing_network_ids == (existing,)
    assert result.network_reconcile.created_network_ids == (missing,)

    synced_rows = db_session.execute(select(ZtNetwork).order_by(ZtNetwork.id.asc())).scalars().all()
    assert [row.id for row in synced_rows] == sorted([existing, missing])
    assert all(row.is_active for row in synced_rows)
    created_row = next(row for row in synced_rows if row.id == missing)
    assert created_row.name == f"ZT Network {missing}"


def test_network_reconciliation_failure_blocks_preflight(
    db_session: Session,
    tmp_path: Path,
) -> None:
    missing = "0123456789abcdef"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{missing}" and request.method == "GET":
            return httpx.Response(status_code=404, json={"error": "missing"})
        if request.url.path == f"/controller/network/{missing}" and request.method == "POST":
            return httpx.Response(status_code=500, json={"error": "boom"})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(missing,),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_network_reconcile_fail",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.network_reconciliation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_token_reload_revalidates_preflight(db_session: Session, tmp_path: Path) -> None:
    token_file = tmp_path / "authtoken.secret"
    token_file.write_text("rotated-token\n", encoding="utf-8")
    required_network = "abcdef0123456789"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-ZT1-Auth"] == "rotated-token"
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{required_network}":
            return httpx.Response(status_code=200, json={"id": required_network})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(required_network,),
        auth_token="old-token",
        auth_token_file=str(token_file),
    )
    token = run_controller_token_reload(
        manager=manager,
        db_session=db_session,
        trigger="test_reload",
    )
    assert token == "rotated-token"

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.token_reload.succeeded" in actions
    assert "controller_lifecycle.preflight.succeeded" in actions


def test_token_reload_failure_is_audited(db_session: Session, tmp_path: Path) -> None:
    manager = _manager(
        tmp_path=tmp_path,
        handler=lambda _: httpx.Response(status_code=200, json={"status": "ok"}),
        required_network_ids=(),
        auth_token_file=str(tmp_path / "missing.secret"),
    )
    with pytest.raises(ControllerTokenReloadError):
        run_controller_token_reload(
            manager=manager,
            db_session=db_session,
            trigger="test_reload_fail",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.token_reload.failed" in actions


def test_backup_retention_and_restore_validation_drill(
    db_session: Session,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    _write_controller_state(state_dir, token_value="token-a")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    for name in ("zt_controller_20260101T000000Z_old1", "zt_controller_20260102T000000Z_old2"):
        (backup_dir / name).mkdir()

    required_network = "abcdef0123456789"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{required_network}":
            return httpx.Response(status_code=200, json={"id": required_network})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(required_network,),
        backup_dir=str(backup_dir),
        backup_retention_count=2,
        state_dir=str(state_dir),
    )
    backup_result = run_controller_backup(
        manager=manager,
        db_session=db_session,
        trigger="test_backup",
    )
    assert len(backup_result.copied_artifacts) == 4
    remaining_backups = sorted(path.name for path in backup_dir.iterdir() if path.is_dir())
    assert len(remaining_backups) == 2

    (state_dir / "identity.public").write_text("mutated", encoding="utf-8")
    restore_result = run_controller_restore_validation_drill(
        manager=manager,
        db_session=db_session,
        trigger="test_restore_validate",
        backup_path=backup_result.backup_path,
    )
    assert restore_result.restored_from == backup_result.backup_path
    assert (state_dir / "identity.public").read_text(encoding="utf-8") == "public"

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.backup.succeeded" in actions
    assert "controller_lifecycle.restore.succeeded" in actions
    assert "controller_lifecycle.restore_validation.succeeded" in actions


def test_restore_validation_failure_keeps_workflow_blocked(
    db_session: Session,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    _write_controller_state(state_dir, token_value="token-a")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=500, json={"error": "unhealthy"})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        backup_dir=str(backup_dir),
        state_dir=str(state_dir),
    )
    backup_result = run_controller_backup(
        manager=manager,
        db_session=db_session,
        trigger="test_backup_for_restore_fail",
    )

    with pytest.raises(ControllerRestoreError):
        run_controller_restore_validation_drill(
            manager=manager,
            db_session=db_session,
            trigger="test_restore_validate_fail",
            backup_path=backup_result.backup_path,
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.restore_validation.failed" in actions


def test_suffix_expansion_uses_controller_prefix_for_reconciliation(
    db_session: Session,
    tmp_path: Path,
) -> None:
    suffix_existing = "123456"
    suffix_missing = "654321"
    existing = f"{CONTROLLER_ID}{suffix_existing}"
    missing = f"{CONTROLLER_ID}{suffix_missing}"
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        if request.url.path == f"/controller/network/{existing}":
            return httpx.Response(status_code=200, json={"id": existing})
        if request.url.path == f"/controller/network/{missing}" and request.method == "GET":
            return httpx.Response(status_code=404, json={"error": "missing"})
        if request.url.path == f"/controller/network/{missing}" and request.method == "POST":
            return httpx.Response(status_code=200, json={"id": missing})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=(suffix_existing, suffix_missing),
        ipv6_prefixes_by_network_suffix=(
            (suffix_existing, "2001:db8:100::/64"),
            (suffix_missing, "2001:db8:200::/64"),
        ),
    )
    result = run_controller_lifecycle_preflight(
        manager=manager,
        db_session=db_session,
        strict_fail_closed=True,
        trigger="test_suffix_expansion",
    )

    assert result is not None
    assert result.network_reconcile.existing_network_ids == (existing,)
    assert result.network_reconcile.created_network_ids == (missing,)
    assert ("GET", f"/controller/network/{existing}") in seen
    assert ("POST", f"/controller/network/{missing}") in seen

    derivation_event = db_session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "controller_lifecycle.required_network_derivation.succeeded")
        .order_by(AuditEvent.created_at.asc())
    ).scalars().all()[-1]
    assert derivation_event.event_metadata["controller_prefix"] == CONTROLLER_ID
    assert derivation_event.event_metadata["required_network_ids"] == [existing, missing]
    assert derivation_event.event_metadata["expanded_suffix_network_ids"] == [existing, missing]


def test_suffix_derivation_rejects_missing_ipv6_prefix_mapping(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=("123abc",),
        ipv6_prefixes_by_network_suffix=(),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_missing_ipv6_mapping",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_suffix_derivation_rejects_non_64_ipv6_prefix_mapping(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=("123abc",),
        ipv6_prefixes_by_network_suffix=(("123abc", "2001:db8:100::/56"),),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_bad_ipv6_prefix",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_suffix_derivation_rejects_extra_ipv6_prefix_mapping_suffix(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=("123abc",),
        ipv6_prefixes_by_network_suffix=(
            ("123abc", "2001:db8:100::/64"),
            ("456def", "2001:db8:200::/64"),
        ),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_extra_ipv6_mapping",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_suffix_derivation_rejects_malformed_suffix(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=("abc12z",),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_malformed",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_suffix_derivation_rejects_duplicate_suffix(
    db_session: Session,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(),
        required_network_suffixes=("123abc", "123abc"),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_duplicate",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def test_suffix_derivation_rejects_mixed_full_id_repetition(
    db_session: Session,
    tmp_path: Path,
) -> None:
    suffix = "123abc"
    full_network_id = f"{CONTROLLER_ID}{suffix}"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status":
            return httpx.Response(status_code=200, json={"status": "online"})
        if request.url.path == "/controller":
            return httpx.Response(status_code=200, json={"id": CONTROLLER_ID})
        raise AssertionError(f"unexpected request {request.method} {request.url.path}")

    manager = _manager(
        tmp_path=tmp_path,
        handler=handler,
        required_network_ids=(full_network_id,),
        required_network_suffixes=(suffix,),
        ipv6_prefixes_by_network_suffix=((suffix, "2001:db8:100::/64"),),
    )
    with pytest.raises(ControllerLifecycleGateError):
        run_controller_lifecycle_preflight(
            manager=manager,
            db_session=db_session,
            strict_fail_closed=True,
            trigger="test_suffix_overlap",
        )

    actions = _audit_actions(db_session)
    assert "controller_lifecycle.required_network_derivation.failed" in actions
    assert "controller_lifecycle.preflight.failed" in actions


def _manager(
    *,
    tmp_path: Path,
    handler: Callable[[httpx.Request], httpx.Response],
    required_network_ids: tuple[str, ...],
    required_network_suffixes: tuple[str, ...] = (),
    ipv6_prefixes_by_network_suffix: tuple[tuple[str, str], ...] = (),
    auth_token: str = "token-controller",
    auth_token_file: str = "",
    backup_dir: str | None = None,
    backup_retention_count: int = 14,
    state_dir: str | None = None,
) -> SelfHostedControllerLifecycleManager:
    return SelfHostedControllerLifecycleManager(
        base_url="http://127.0.0.1:9993/controller",
        auth_token=auth_token,
        required_network_suffixes=required_network_suffixes,
        ipv6_prefixes_by_network_suffix=ipv6_prefixes_by_network_suffix,
        required_network_ids=required_network_ids,
        backup_dir=backup_dir or str(tmp_path / "backups"),
        backup_retention_count=backup_retention_count,
        controller_state_dir=state_dir or str(tmp_path / "state"),
        auth_token_file=auth_token_file,
        http_client_factory=_mock_client_factory(handler),
    )


def _mock_client_factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[..., httpx.Client]:
    def factory(**kwargs: Any) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)

    return factory


def _write_controller_state(state_dir: Path, *, token_value: str) -> None:
    controller_dir = state_dir / "controller.d"
    controller_dir.mkdir(parents=True, exist_ok=True)
    (controller_dir / "network.json").write_text("{}", encoding="utf-8")
    (state_dir / "identity.public").write_text("public", encoding="utf-8")
    (state_dir / "identity.secret").write_text("secret", encoding="utf-8")
    (state_dir / "authtoken.secret").write_text(token_value, encoding="utf-8")


def _audit_actions(db_session: Session) -> list[str]:
    return list(
        db_session.execute(select(AuditEvent.action).order_by(AuditEvent.created_at.asc())).scalars()
    )
