"""phase 3 auth option a schema

Revision ID: 20260210_0002
Revises: 20260210_0001
Create Date: 2026-02-10 19:30:00

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260210_0002"
down_revision: str | None = "20260210_0001"
branch_labels: str | None = None
depends_on: str | None = None


def _uuid_column(name: str, dialect_name: str) -> sa.Column[sa.Uuid]:
    kwargs: dict[str, object] = {"nullable": False, "primary_key": True}
    if dialect_name == "postgresql":
        kwargs["server_default"] = sa.text("gen_random_uuid()")
    return sa.Column(name, sa.Uuid(), **kwargs)


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        with op.batch_alter_table("app_user") as batch_op:
            batch_op.alter_column(
                "peeringdb_user_id",
                existing_type=sa.BigInteger(),
                nullable=True,
            )
    else:
        op.alter_column(
            "app_user",
            "peeringdb_user_id",
            existing_type=sa.BigInteger(),
            nullable=True,
        )

    op.create_table(
        "local_credential",
        _uuid_column("id", dialect_name),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("login_username", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "login_username = lower(login_username)",
            name="ck_local_credential_local_credential_login_username_lower",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name="fk_local_credential_user_id_app_user",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_local_credential"),
        sa.UniqueConstraint("login_username", name="uq_local_credential_login_username"),
        sa.UniqueConstraint("user_id", name="uq_local_credential_user_id"),
    )
    op.create_index(
        "idx_local_credential_user_id",
        "local_credential",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "user_network_access",
        _uuid_column("id", dialect_name),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("zt_network_id", sa.String(length=16), nullable=False),
        sa.Column("source", sa.Text(), nullable=False, server_default=sa.text("'local'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name="fk_user_network_access_user_id_app_user",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["zt_network_id"],
            ["zt_network.id"],
            name="fk_user_network_access_zt_network_id_zt_network",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_network_access"),
        sa.UniqueConstraint("user_id", "zt_network_id", name="uq_user_network_access_user_id"),
    )
    op.create_index(
        "idx_user_network_access_user_id",
        "user_network_access",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_user_network_access_user_id", table_name="user_network_access")
    op.drop_table("user_network_access")

    op.drop_index("idx_local_credential_user_id", table_name="local_credential")
    op.drop_table("local_credential")

    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        with op.batch_alter_table("app_user") as batch_op:
            batch_op.alter_column(
                "peeringdb_user_id",
                existing_type=sa.BigInteger(),
                nullable=False,
            )
    else:
        op.alter_column(
            "app_user",
            "peeringdb_user_id",
            existing_type=sa.BigInteger(),
            nullable=False,
        )
