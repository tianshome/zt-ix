"""add deterministic IPv6 allocation persistence tables

Revision ID: 20260212_0004
Revises: 20260212_0003
Create Date: 2026-02-12 11:30:00

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260212_0004"
down_revision: str | None = "20260212_0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "zt_ipv6_allocation_state",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("zt_network_id", sa.String(length=16), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=False),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["zt_network_id"],
            ["zt_network.id"],
            name="fk_zt_ipv6_allocation_state_zt_network_id_zt_network",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_zt_ipv6_allocation_state"),
        sa.UniqueConstraint(
            "zt_network_id",
            "asn",
            name="uq_zt_ipv6_allocation_state_zt_network_id",
        ),
    )
    op.create_table(
        "zt_ipv6_assignment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("join_request_id", sa.Uuid(), nullable=False),
        sa.Column("zt_network_id", sa.String(length=16), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("assigned_ip", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("sequence > 0", name="ck_zt_ipv6_assignment_sequence_positive"),
        sa.ForeignKeyConstraint(
            ["join_request_id"],
            ["join_request.id"],
            name="fk_zt_ipv6_assignment_join_request_id_join_request",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["zt_network_id"],
            ["zt_network.id"],
            name="fk_zt_ipv6_assignment_zt_network_id_zt_network",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_zt_ipv6_assignment"),
        sa.UniqueConstraint("join_request_id", name="uq_zt_ipv6_assignment_join_request_id"),
        sa.UniqueConstraint(
            "zt_network_id",
            "asn",
            "sequence",
            name="uq_zt_ipv6_assignment_zt_network_id",
        ),
        sa.UniqueConstraint(
            "zt_network_id",
            "assigned_ip",
            name="uq_zt_ipv6_assignment_zt_network_id_assigned_ip",
        ),
    )


def downgrade() -> None:
    op.drop_table("zt_ipv6_assignment")
    op.drop_table("zt_ipv6_allocation_state")
