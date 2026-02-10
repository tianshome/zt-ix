"""Server CLI for self-hosted ZeroTier controller lifecycle operations."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import session_scope
from app.provisioning.controller_lifecycle import (
    ControllerBackupResult,
    ControllerLifecycleError,
    ControllerRestoreResult,
    create_controller_lifecycle_manager,
    run_controller_backup,
    run_controller_lifecycle_preflight,
    run_controller_restore,
    run_controller_restore_validation_drill,
    run_controller_token_reload,
)

type SessionScopeFactory = Callable[[], AbstractContextManager[Session]]


class CliValidationError(ValueError):
    """Raised when lifecycle CLI input or mode validation fails."""


def main(
    argv: Sequence[str] | None = None,
    *,
    session_scope_factory: SessionScopeFactory | None = None,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    scope_factory = session_scope_factory or session_scope

    try:
        settings = get_settings()
        if settings.zt_provider.strip().lower() != "self_hosted_controller":
            raise CliValidationError(
                "controller lifecycle commands require ZT_PROVIDER=self_hosted_controller"
            )
        manager = create_controller_lifecycle_manager(settings)

        with scope_factory() as db_session:
            if args.command == "preflight":
                run_controller_lifecycle_preflight(
                    manager=manager,
                    db_session=db_session,
                    strict_fail_closed=True,
                    trigger="cli_preflight",
                )
                print("controller lifecycle preflight succeeded")
                return 0

            if args.command == "reload-token":
                run_controller_token_reload(
                    manager=manager,
                    db_session=db_session,
                    trigger="cli_reload_token",
                    token_file=args.token_file,
                )
                print("controller token reload and validation succeeded")
                return 0

            if args.command == "backup":
                backup_result = run_controller_backup(
                    manager=manager,
                    db_session=db_session,
                    trigger="cli_backup",
                )
                _print_backup_result(backup_result)
                return 0

            if args.command == "restore":
                restore_result = run_controller_restore(
                    manager=manager,
                    db_session=db_session,
                    trigger="cli_restore",
                    backup_path=args.backup_path,
                )
                _print_restore_result(restore_result)
                return 0

            if args.command == "restore-validate":
                restore_result = run_controller_restore_validation_drill(
                    manager=manager,
                    db_session=db_session,
                    trigger="cli_restore_validate",
                    backup_path=args.backup_path,
                )
                _print_restore_result(restore_result)
                print("restore validation drill passed")
                return 0

            raise CliValidationError(f"unsupported command: {args.command}")
    except (CliValidationError, ControllerLifecycleError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli.controller_lifecycle")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", help="run controller readiness + network reconciliation")

    reload_token_parser = subparsers.add_parser(
        "reload-token",
        help="reload controller auth token from file and validate preflight",
    )
    reload_token_parser.add_argument("--token-file")

    subparsers.add_parser("backup", help="backup controller state artifacts")

    restore_parser = subparsers.add_parser("restore", help="restore controller state from backup")
    restore_parser.add_argument("--backup-path", required=True)

    restore_validate_parser = subparsers.add_parser(
        "restore-validate",
        help="restore state and run readiness/reconciliation validation drill",
    )
    restore_validate_parser.add_argument("--backup-path", required=True)

    return parser


def _print_backup_result(result: ControllerBackupResult) -> None:
    print(
        f"controller backup created path={result.backup_path} "
        f"copied={len(result.copied_artifacts)} pruned={len(result.pruned_backup_paths)}"
    )


def _print_restore_result(result: ControllerRestoreResult) -> None:
    print(
        f"controller state restored from={result.restored_from} "
        f"artifacts={len(result.restored_artifacts)}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
