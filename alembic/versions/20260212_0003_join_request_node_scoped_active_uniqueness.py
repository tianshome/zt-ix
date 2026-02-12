"""join request active uniqueness scoped by node id

Revision ID: 20260212_0003
Revises: 20260210_0002
Create Date: 2026-02-12 06:45:00

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260212_0003"
down_revision: str | None = "20260210_0002"
branch_labels: str | None = None
depends_on: str | None = None

ACTIVE_STATUS_WHERE = "status IN ('pending', 'approved', 'provisioning', 'active')"
ACTIVE_STATUS_WITH_NODE_WHERE = (
    "status IN ('pending', 'approved', 'provisioning', 'active') AND node_id IS NOT NULL"
)
ACTIVE_STATUS_WITHOUT_NODE_WHERE = (
    "status IN ('pending', 'approved', 'provisioning', 'active') AND node_id IS NULL"
)


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    op.drop_index("uq_join_request_active_per_asn_network", table_name="join_request")

    if dialect_name == "postgresql":
        op.create_index(
            "uq_join_request_active_per_asn_network_with_node",
            "join_request",
            ["asn", "zt_network_id", "node_id"],
            unique=True,
            postgresql_where=sa.text(ACTIVE_STATUS_WITH_NODE_WHERE),
        )
        op.create_index(
            "uq_join_request_active_per_asn_network_without_node",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
            postgresql_where=sa.text(ACTIVE_STATUS_WITHOUT_NODE_WHERE),
        )
    elif dialect_name == "sqlite":
        op.create_index(
            "uq_join_request_active_per_asn_network_with_node",
            "join_request",
            ["asn", "zt_network_id", "node_id"],
            unique=True,
            sqlite_where=sa.text(ACTIVE_STATUS_WITH_NODE_WHERE),
        )
        op.create_index(
            "uq_join_request_active_per_asn_network_without_node",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
            sqlite_where=sa.text(ACTIVE_STATUS_WITHOUT_NODE_WHERE),
        )
    else:
        op.create_index(
            "uq_join_request_active_per_asn_network_with_node",
            "join_request",
            ["asn", "zt_network_id", "node_id"],
            unique=True,
        )
        op.create_index(
            "uq_join_request_active_per_asn_network_without_node",
            "join_request",
            ["asn", "zt_network_id"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    op.drop_index("uq_join_request_active_per_asn_network_without_node", table_name="join_request")
    op.drop_index("uq_join_request_active_per_asn_network_with_node", table_name="join_request")

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
