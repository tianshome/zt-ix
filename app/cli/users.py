"""Server CLI for local-auth user provisioning."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager

from sqlalchemy.orm import Session

from app.auth import (
    LocalPasswordPolicyError,
    hash_password,
    normalize_login_username,
)
from app.config import get_settings
from app.db.session import session_scope
from app.repositories.audit_events import AuditEventRepository
from app.repositories.local_credentials import LocalCredentialRepository
from app.repositories.user_asns import UserAsnRecord, UserAsnRepository
from app.repositories.user_network_access import UserNetworkAccessRepository
from app.repositories.users import UserRepository
from app.repositories.zt_networks import ZtNetworkRepository

type SessionScopeFactory = Callable[[], AbstractContextManager[Session]]


class CliValidationError(ValueError):
    """Raised when CLI input fails validation."""


def main(
    argv: Sequence[str] | None = None,
    *,
    session_scope_factory: SessionScopeFactory | None = None,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    scope_factory = session_scope_factory or session_scope

    if args.command != "create":
        parser.error(f"unsupported command: {args.command}")

    try:
        return _run_create(args, scope_factory=scope_factory)
    except CliValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli.users")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="create or update a local-auth account")
    create_parser.add_argument("--username", required=True)

    password_group = create_parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument("--password")
    password_group.add_argument("--password-stdin", action="store_true")

    admin_group = create_parser.add_mutually_exclusive_group()
    admin_group.add_argument("--admin", action="store_true")
    admin_group.add_argument("--no-admin", action="store_true")

    create_parser.add_argument("--asn", action="append", type=int, default=[])
    create_parser.add_argument("--zt-network-id", action="append", default=[])
    create_parser.add_argument("--full-name")
    create_parser.add_argument("--email")
    return parser


def _run_create(args: argparse.Namespace, *, scope_factory: SessionScopeFactory) -> int:
    normalized_username = normalize_login_username(args.username)
    password = _resolve_password(args)
    asn_records = _normalize_asn_records(args.asn)
    network_ids = _normalize_network_ids(args.zt_network_id)
    is_admin = _resolve_admin_flag(args)

    settings = get_settings()
    try:
        password_hash = hash_password(
            password=password,
            min_length=settings.local_auth_password_min_length,
            iterations=settings.local_auth_pbkdf2_iterations,
        )
    except LocalPasswordPolicyError as exc:
        raise CliValidationError(str(exc)) from exc

    summary: str
    with scope_factory() as db_session:
        user_repo = UserRepository(db_session)
        credential_repo = LocalCredentialRepository(db_session)
        asn_repo = UserAsnRepository(db_session)
        network_access_repo = UserNetworkAccessRepository(db_session)
        network_repo = ZtNetworkRepository(db_session)
        audit_repo = AuditEventRepository(db_session)

        user = user_repo.upsert_local_user(
            username=normalized_username,
            full_name=_normalize_optional_value(args.full_name),
            email=_normalize_optional_value(args.email),
            is_admin=is_admin,
        )

        existing_credential = credential_repo.get_by_login_username(normalized_username)
        if existing_credential is not None and existing_credential.user_id != user.id:
            raise CliValidationError("duplicate username")

        credential_repo.upsert_for_user(
            user_id=user.id,
            login_username=normalized_username,
            password_hash=password_hash,
            is_enabled=True,
        )
        asn_repo.replace_for_user(user.id, asn_records)

        for network_id in network_ids:
            if network_repo.get_by_id(network_id) is None:
                raise CliValidationError(f"unknown zt_network_id: {network_id}")
        network_access_repo.replace_for_user(user.id, network_ids, source="local")

        audit_repo.create_event(
            action="auth.local_account.provisioned",
            target_type="app_user",
            target_id=str(user.id),
            metadata={
                "username": normalized_username,
                "is_admin": user.is_admin,
                "asn_count": len(asn_records),
                "network_access_count": len(network_ids),
            },
        )

        summary = (
            f"provisioned local user username={normalized_username} "
            f"user_id={user.id} asns={len(asn_records)} networks={len(network_ids)} "
            f"is_admin={user.is_admin}"
        )

    print(summary)
    return 0


def _resolve_password(args: argparse.Namespace) -> str:
    if bool(args.password_stdin):
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = args.password or ""
    if not password:
        raise CliValidationError("password is required")
    return password


def _normalize_asn_records(asn_values: Sequence[int]) -> list[UserAsnRecord]:
    records: list[UserAsnRecord] = []
    seen: set[int] = set()
    for asn in asn_values:
        if asn <= 0:
            raise CliValidationError(f"invalid ASN: {asn}")
        if asn in seen:
            continue
        seen.add(asn)
        records.append(UserAsnRecord(asn=asn, source="local"))
    return records


def _normalize_network_ids(network_values: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in network_values:
        value = raw.strip().lower()
        if len(value) != 16:
            raise CliValidationError(f"invalid zt_network_id: {raw}")
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _resolve_admin_flag(args: argparse.Namespace) -> bool | None:
    if bool(args.admin):
        return True
    if bool(args.no_admin):
        return False
    return None


def _normalize_optional_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


if __name__ == "__main__":
    raise SystemExit(main())
