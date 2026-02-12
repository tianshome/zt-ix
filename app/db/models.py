"""SQLAlchemy ORM models for ZT-IX data contracts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.enums import RequestStatus

REQUEST_STATUS_ENUM = Enum(
    RequestStatus,
    name="request_status",
    values_callable=lambda enum_cls: [status.value for status in enum_cls],
)
ASSIGNED_IPS_TYPE = ARRAY(Text()).with_variant(JSON(), "sqlite")
AUDIT_METADATA_TYPE = JSONB().with_variant(JSON(), "sqlite")  # type: ignore[no-untyped-call]


class AppUser(Base):
    __tablename__ = "app_user"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    peeringdb_user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, unique=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(Text)
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    local_credential: Mapped[LocalCredential | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    asns: Mapped[list[UserAsn]] = relationship(back_populates="user", cascade="all, delete-orphan")
    network_access: Mapped[list[UserNetworkAccess]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    requests: Mapped[list[JoinRequest]] = relationship(back_populates="user")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="actor_user")


class LocalCredential(Base):
    __tablename__ = "local_credential"
    __table_args__ = (
        CheckConstraint(
            "login_username = lower(login_username)",
            name="local_credential_login_username_lower",
        ),
        Index("idx_local_credential_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("app_user.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    login_username: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped[AppUser] = relationship(back_populates="local_credential")


class UserAsn(Base):
    __tablename__ = "user_asn"
    __table_args__ = (UniqueConstraint("user_id", "asn"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("app_user.id", ondelete="CASCADE"),
        nullable=False,
    )
    asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    net_id: Mapped[int | None] = mapped_column(BigInteger)
    net_name: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="peeringdb",
        server_default=text("'peeringdb'"),
    )
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped[AppUser] = relationship(back_populates="asns")


class ZtNetwork(Base):
    __tablename__ = "zt_network"
    __table_args__ = (CheckConstraint("length(id) = 16", name="zt_network_id_len"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user_access: Mapped[list[UserNetworkAccess]] = relationship(back_populates="zt_network")
    requests: Mapped[list[JoinRequest]] = relationship(back_populates="zt_network")
    memberships: Mapped[list[ZtMembership]] = relationship(back_populates="zt_network")


class UserNetworkAccess(Base):
    __tablename__ = "user_network_access"
    __table_args__ = (
        UniqueConstraint("user_id", "zt_network_id"),
        Index("idx_user_network_access_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("app_user.id", ondelete="CASCADE"),
        nullable=False,
    )
    zt_network_id: Mapped[str] = mapped_column(
        String(16),
        ForeignKey("zt_network.id", ondelete="CASCADE"),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="local",
        server_default=text("'local'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped[AppUser] = relationship(back_populates="network_access")
    zt_network: Mapped[ZtNetwork] = relationship(back_populates="user_access")


class JoinRequest(Base):
    __tablename__ = "join_request"
    __table_args__ = (
        CheckConstraint("node_id IS NULL OR length(node_id) = 10", name="join_request_node_id_len"),
        Index("idx_join_request_status", "status"),
        Index("idx_join_request_user", "user_id"),
        Index(
            "uq_join_request_active_per_asn_network_with_node",
            "asn",
            "zt_network_id",
            "node_id",
            unique=True,
            postgresql_where=text(
                "status IN ('pending', 'approved', 'provisioning', 'active') "
                "AND node_id IS NOT NULL"
            ),
            sqlite_where=text(
                "status IN ('pending', 'approved', 'provisioning', 'active') "
                "AND node_id IS NOT NULL"
            ),
        ),
        Index(
            "uq_join_request_active_per_asn_network_without_node",
            "asn",
            "zt_network_id",
            unique=True,
            postgresql_where=text(
                "status IN ('pending', 'approved', 'provisioning', 'active') "
                "AND node_id IS NULL"
            ),
            sqlite_where=text(
                "status IN ('pending', 'approved', 'provisioning', 'active') "
                "AND node_id IS NULL"
            ),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    zt_network_id: Mapped[str] = mapped_column(
        String(16),
        ForeignKey("zt_network.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[RequestStatus] = mapped_column(
        REQUEST_STATUS_ENUM,
        nullable=False,
        default=RequestStatus.PENDING,
        server_default=text("'pending'"),
    )
    node_id: Mapped[str | None] = mapped_column(String(10))
    notes: Mapped[str | None] = mapped_column(Text)
    reject_reason: Mapped[str | None] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped[AppUser] = relationship(back_populates="requests")
    zt_network: Mapped[ZtNetwork] = relationship(back_populates="requests")
    membership: Mapped[ZtMembership | None] = relationship(
        back_populates="join_request",
        uselist=False,
        cascade="all, delete-orphan",
    )


class ZtMembership(Base):
    __tablename__ = "zt_membership"
    __table_args__ = (
        CheckConstraint("length(node_id) = 10", name="zt_membership_node_id_len"),
        UniqueConstraint("zt_network_id", "node_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    join_request_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("join_request.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    zt_network_id: Mapped[str] = mapped_column(
        String(16),
        ForeignKey("zt_network.id", ondelete="RESTRICT"),
        nullable=False,
    )
    node_id: Mapped[str] = mapped_column(String(10), nullable=False)
    member_id: Mapped[str] = mapped_column(Text, nullable=False)
    is_authorized: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    assigned_ips: Mapped[list[str]] = mapped_column(ASSIGNED_IPS_TYPE, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    join_request: Mapped[JoinRequest] = relationship(back_populates="membership")
    zt_network: Mapped[ZtNetwork] = relationship(back_populates="memberships")


class OauthStateNonce(Base):
    __tablename__ = "oauth_state_nonce"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    state: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    nonce: Mapped[str] = mapped_column(Text, nullable=False)
    pkce_verifier: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (Index("idx_audit_event_created_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("app_user.id", ondelete="SET NULL"),
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        AUDIT_METADATA_TYPE,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    actor_user: Mapped[AppUser | None] = relationship(back_populates="audit_events")
