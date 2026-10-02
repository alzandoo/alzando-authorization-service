from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import Uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("application_id", "id", name="uq_roles_application_id_id"),
        UniqueConstraint("application_id", "name", name="uq_roles_application_name"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("application_id", "id", name="uq_permissions_application_id_id"),
        UniqueConstraint("application_id", "key", name="uq_permissions_application_key"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "role_id"], ["roles.application_id", "roles.id"],
            ondelete="CASCADE", name="fk_role_permissions_role",
        ),
        ForeignKeyConstraint(
            ["application_id", "permission_id"], ["permissions.application_id", "permissions.id"],
            ondelete="CASCADE", name="fk_role_permissions_permission",
        ),
        Index("ix_role_permissions_application_role", "application_id", "role_id"),
    )

    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    permission_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "role_id"], ["roles.application_id", "roles.id"],
            ondelete="CASCADE", name="fk_user_roles_role",
        ),
        Index("ix_user_roles_application_user", "application_id", "user_reference"),
    )

    application_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_reference: Mapped[str] = mapped_column(String(200), primary_key=True)
    role_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)


class ApplicationClient(Base):
    __tablename__ = "application_clients"

    client_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    client_secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
