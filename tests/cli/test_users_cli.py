from __future__ import annotations

import io
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.auth import verify_password
from app.cli import users as users_cli
from app.config import get_settings
from app.db.models import (
    AppUser,
    AuditEvent,
    LocalCredential,
    UserAsn,
    UserNetworkAccess,
    ZtNetwork,
)


@pytest.fixture(autouse=True)
def clear_settings_cache() -> Generator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_cli_create_provisions_local_user_and_assignments(
    session_factory: sessionmaker[Session],
    session_scope_factory: Callable[[], AbstractContextManager[Session]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _seed_network(session_factory, "abcdef0123456789")

    exit_code = users_cli.main(
        [
            "create",
            "--username",
            " Local-Admin ",
            "--password",
            "correct horse battery staple",
            "--admin",
            "--asn",
            "64512",
            "--asn",
            "64513",
            "--zt-network-id",
            "abcdef0123456789",
        ],
        session_scope_factory=session_scope_factory,
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "provisioned local user username=local-admin" in out

    with session_factory() as session:
        user = session.execute(
            select(AppUser).where(AppUser.username == "local-admin")
        ).scalar_one()
        assert user.is_admin is True
        assert user.peeringdb_user_id is None

        credential = session.execute(
            select(LocalCredential).where(LocalCredential.user_id == user.id)
        ).scalar_one()
        assert credential.login_username == "local-admin"
        assert verify_password(
            password="correct horse battery staple",
            encoded_hash=credential.password_hash,
        )

        asn_rows = session.execute(
            select(UserAsn).where(UserAsn.user_id == user.id)
        ).scalars().all()
        assert {row.asn for row in asn_rows} == {64512, 64513}

        access_rows = (
            session.execute(select(UserNetworkAccess).where(UserNetworkAccess.user_id == user.id))
            .scalars()
            .all()
        )
        assert [row.zt_network_id for row in access_rows] == ["abcdef0123456789"]

        audit_event = session.execute(
            select(AuditEvent).where(AuditEvent.action == "auth.local_account.provisioned")
        ).scalar_one()
        assert audit_event.target_id == str(user.id)


def test_cli_create_rejects_unknown_network_and_rolls_back(
    session_factory: sessionmaker[Session],
    session_scope_factory: Callable[[], AbstractContextManager[Session]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = users_cli.main(
        [
            "create",
            "--username",
            "rollback-user",
            "--password",
            "rollback password value",
            "--asn",
            "64512",
            "--zt-network-id",
            "abcdef0123456789",
        ],
        session_scope_factory=session_scope_factory,
    )

    assert exit_code == 2
    err = capsys.readouterr().err
    assert "unknown zt_network_id: abcdef0123456789" in err

    with session_factory() as session:
        assert session.execute(select(AppUser)).scalar_one_or_none() is None
        assert session.execute(select(LocalCredential)).scalar_one_or_none() is None


def test_cli_create_enforces_password_policy(
    session_factory: sessionmaker[Session],
    session_scope_factory: Callable[[], AbstractContextManager[Session]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _write_runtime_config(
        tmp_path,
        "auth:\n  local_auth:\n    password_min_length: 16\n",
    )
    monkeypatch.chdir(tmp_path)

    exit_code = users_cli.main(
        [
            "create",
            "--username",
            "policy-user",
            "--password",
            "too-short",
        ],
        session_scope_factory=session_scope_factory,
    )

    assert exit_code == 2
    err = capsys.readouterr().err
    assert "password must be at least 16 characters" in err

    with session_factory() as session:
        assert session.execute(select(AppUser)).scalar_one_or_none() is None


def test_cli_create_supports_password_stdin(
    session_factory: sessionmaker[Session],
    session_scope_factory: Callable[[], AbstractContextManager[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin password value\n"))

    exit_code = users_cli.main(
        [
            "create",
            "--username",
            "stdin-user",
            "--password-stdin",
            "--asn",
            "64512",
        ],
        session_scope_factory=session_scope_factory,
    )
    assert exit_code == 0

    with session_factory() as session:
        user = session.execute(select(AppUser).where(AppUser.username == "stdin-user")).scalar_one()
        credential = session.execute(
            select(LocalCredential).where(LocalCredential.user_id == user.id)
        ).scalar_one()
        assert verify_password(
            password="stdin password value",
            encoded_hash=credential.password_hash,
        )


def _seed_network(session_factory: sessionmaker[Session], network_id: str) -> None:
    with session_factory() as session:
        session.add(ZtNetwork(id=network_id, name="Network", is_active=True))
        session.commit()


def _write_runtime_config(tmp_path: Path, content: str) -> Path:
    runtime_config = tmp_path / "runtime-config.yaml"
    runtime_config.write_text(content, encoding="utf-8")
    return runtime_config
