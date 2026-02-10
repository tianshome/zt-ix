"""phase 2 data foundation

Revision ID: 20260210_0001
Revises:
Create Date: 2026-02-10 00:00:01

"""

from __future__ import annotations

from typing import Final

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260210_0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

ACTIVE_STATUS_WHERE: Final[str] = "status IN ('pending', 'approved', 'provisioning', 'active')"


def _uuid_column(name: str, dialect_name: str) -> sa.Column[sa.Uuid]:
    kwargs: dict[str, object] = {"nullable": False, "primary_key": True}
    if dialect_name == "postgresql":
        kwargs["server_default"] = sa.text("gen_random_uuid()")
    return sa.Column(name, sa.Uuid(), **kwargs)


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "postgresql":
        op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    request_status_enum = sa.Enum(
        "pending",
        "approved",
        "provisioning",
        "active",
        "rejected",
        "failed",
        name="request_status",
    )
    assigned_ips_type: sa.TypeEngine[object]
    assigned_ips_default: sa.TextClause
    audit_metadata_type: sa.TypeEngine[object]
    audit_metadata_default: sa.TextClause

    if dialect_name == "postgresql":
        assigned_ips_type = postgresql.ARRAY(sa.Text())
        assigned_ips_default = sa.text("'{}'::text[]")
        audit_metadata_type = postgresql.JSONB()
        audit_metadata_default = sa.text("'{}'::jsonb")
    else:
        assigned_ips_type = sa.JSON()
        assigned_ips_default = sa.text("'[]'")
        audit_metadata_type = sa.JSON()
        audit_metadata_default = sa.text("'{}'")

    op.create_table(
        "app_user",
        _uuid_column("id", dialect_name),
        sa.Column("peeringdb_user_id", sa.BigInteger(), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("full_name", sa.Text(), nullable=True),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
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
        sa.PrimaryKeyConstraint("id", name="pk_app_user"),
        sa.UniqueConstraint("peeringdb_user_id", name="uq_app_user_peeringdb_user_id"),
    )

    op.create_table(
        "zt_network",
        sa.Column("id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.CheckConstraint("length(id) = 16", name="ck_zt_network_zt_network_id_len"),
        sa.PrimaryKeyConstraint("id", name="pk_zt_network"),
    )

    op.create_table(
        "oauth_state_nonce",
        _uuid_column("id", dialect_name),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("pkce_verifier", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_state_nonce"),
        sa.UniqueConstraint("state", name="uq_oauth_state_nonce_state"),
    )

    op.create_table(
        "user_asn",
        _uuid_column("id", dialect_name),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=False),
        sa.Column("net_id", sa.BigInteger(), nullable=True),
        sa.Column("net_name", sa.Text(), nullable=True),
        sa.Column("source", sa.Text(), nullable=False, server_default=sa.text("'peeringdb'")),
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name="fk_user_asn_user_id_app_user",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_asn"),
        sa.UniqueConstraint("user_id", "asn", name="uq_user_asn_user_id"),
    )

    op.create_table(
        "join_request",
        _uuid_column("id", dialect_name),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=False),
        sa.Column("zt_network_id", sa.String(length=16), nullable=False),
        sa.Column(
            "status",
            request_status_enum,
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("node_id", sa.String(length=10), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("reject_reason", sa.Text(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provisioned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "node_id IS NULL OR length(node_id) = 10",
            name="ck_join_request_join_request_node_id_len",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name="fk_join_request_user_id_app_user",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["zt_network_id"],
            ["zt_network.id"],
            name="fk_join_request_zt_network_id_zt_network",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_join_request"),
    )
    op.create_index("idx_join_request_status", "join_request", ["status"], unique=False)
    op.create_index("idx_join_request_user", "join_request", ["user_id"], unique=False)
    if dialect_name == "postgresql":
        op.create_index(
            "uq_join_request_active_per_asn_network",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
            postgresql_where=sa.text(ACTIVE_STATUS_WHERE),
        )
    elif dialect_name == "sqlite":
        op.create_index(
            "uq_join_request_active_per_asn_network",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
            sqlite_where=sa.text(ACTIVE_STATUS_WHERE),
        )
    else:
        op.create_index(
            "uq_join_request_active_per_asn_network",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
        )

    op.create_table(
        "audit_event",
        _uuid_column("id", dialect_name),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column(
            "metadata",
            audit_metadata_type,
            nullable=False,
            server_default=audit_metadata_default,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["app_user.id"],
            name="fk_audit_event_actor_user_id_app_user",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_event"),
    )
    op.create_index("idx_audit_event_created_at", "audit_event", ["created_at"], unique=False)

    op.create_table(
        "zt_membership",
        _uuid_column("id", dialect_name),
        sa.Column("join_request_id", sa.Uuid(), nullable=False),
        sa.Column("zt_network_id", sa.String(length=16), nullable=False),
        sa.Column("node_id", sa.String(length=10), nullable=False),
        sa.Column("member_id", sa.Text(), nullable=False),
        sa.Column("is_authorized", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "assigned_ips",
            assigned_ips_type,
            nullable=False,
            server_default=assigned_ips_default,
        ),
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
            "length(node_id) = 10",
            name="ck_zt_membership_zt_membership_node_id_len",
        ),
        sa.ForeignKeyConstraint(
            ["join_request_id"],
            ["join_request.id"],
            name="fk_zt_membership_join_request_id_join_request",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["zt_network_id"],
            ["zt_network.id"],
            name="fk_zt_membership_zt_network_id_zt_network",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_zt_membership"),
        sa.UniqueConstraint("join_request_id", name="uq_zt_membership_join_request_id"),
        sa.UniqueConstraint("zt_network_id", "node_id", name="uq_zt_membership_zt_network_id"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    op.drop_table("zt_membership")
    op.drop_index("idx_audit_event_created_at", table_name="audit_event")
    op.drop_table("audit_event")
    op.drop_index("uq_join_request_active_per_asn_network", table_name="join_request")
    op.drop_index("idx_join_request_user", table_name="join_request")
    op.drop_index("idx_join_request_status", table_name="join_request")
    op.drop_table("join_request")
    op.drop_table("user_asn")
    op.drop_table("oauth_state_nonce")
    op.drop_table("zt_network")
    op.drop_table("app_user")

    if dialect_name == "postgresql":
        request_status_enum = sa.Enum(
            "pending",
            "approved",
            "provisioning",
            "active",
            "rejected",
            "failed",
            name="request_status",
        )
        request_status_enum.drop(bind, checkfirst=True)
