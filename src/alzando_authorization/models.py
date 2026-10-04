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
    client_secret_hash: Mapped[str | None] = mapped_column(String(256))
    client_type: Mapped[str] = mapped_column(String(24), nullable=False, default="CONFIDENTIAL")
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Application(Base):
    __tablename__ = "applications"

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000))
    application_type: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Service(Base):
    __tablename__ = "services"

    service_code: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    service_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE")


class ApplicationService(Base):
    __tablename__ = "application_services"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id"], ["applications.application_id"],
            ondelete="CASCADE", name="fk_application_services_application",
        ),
        ForeignKeyConstraint(
            ["service_code"], ["services.service_code"],
            ondelete="RESTRICT", name="fk_application_services_service",
        ),
        Index("ix_application_services_service", "service_code"),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    service_code: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class AuthenticationAccount(Base):
    __tablename__ = "authentication_accounts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id"], ["applications.application_id"],
            ondelete="CASCADE", name="fk_authentication_accounts_application",
        ),
        UniqueConstraint("application_id", "email", name="uq_authentication_accounts_application_email"),
        UniqueConstraint("application_id", "phone", name="uq_authentication_accounts_application_phone"),
        Index("ix_authentication_accounts_application_status", "application_id", "status"),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    account_reference: Mapped[str] = mapped_column(String(96), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(32))
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    phone_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    recovery_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class PasswordRecoveryChallenge(Base):
    __tablename__ = "password_recovery_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_password_recovery_challenges_account",
        ),
        Index(
            "ix_password_recovery_challenges_account_created",
            "application_id", "account_reference", "created_at",
        ),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    recovery_reference: Mapped[str] = mapped_column(String(96), primary_key=True)
    account_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class EmailVerificationChallenge(Base):
    __tablename__ = "email_verification_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_email_verification_challenges_account",
        ),
        Index(
            "ix_email_verification_challenges_account_created",
            "application_id", "account_reference", "created_at",
        ),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    verification_reference: Mapped[str] = mapped_column(String(96), primary_key=True)
    account_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class PhoneVerificationChallenge(Base):
    __tablename__ = "phone_verification_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_phone_verification_challenges_account",
        ),
        Index(
            "ix_phone_verification_challenges_account_created",
            "application_id", "account_reference", "created_at",
        ),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    verification_reference: Mapped[str] = mapped_column(String(96), primary_key=True)
    account_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_otp_challenges_account",
        ),
        Index(
            "ix_otp_challenges_subject_created",
            "application_id", "subject_reference", "purpose", "channel", "created_at",
        ),
    )

    application_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    challenge_reference: Mapped[str] = mapped_column(String(96), primary_key=True)
    subject_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    account_reference: Mapped[str | None] = mapped_column(String(96))
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
