"""Add one-time authentication grants and rotating user sessions.

Revision ID: 0009_user_sessions
Revises: 0008_otp_challenges
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_user_sessions"
down_revision = "0008_otp_challenges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authentication_grants",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("authentication_reference", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=False),
        sa.Column("mfa_required", sa.Boolean(), nullable=False),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_authentication_grants_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "authentication_reference"),
    )
    op.create_index(
        "ix_authentication_grants_account_created", "authentication_grants",
        ["application_id", "account_reference", "created_at"],
    )

    op.add_column(
        "otp_challenges",
        sa.Column("authentication_reference", sa.String(length=96), nullable=True),
    )
    op.create_foreign_key(
        "fk_otp_challenges_authentication_grant", "otp_challenges", "authentication_grants",
        ["application_id", "authentication_reference"],
        ["application_id", "authentication_reference"], ondelete="CASCADE",
    )

    op.create_table(
        "user_sessions",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("session_id", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("mfa_authenticated", sa.Boolean(), nullable=False),
        sa.Column("refresh_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_to_session_id", sa.String(length=96), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_user_sessions_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "session_id"),
        sa.UniqueConstraint("application_id", "refresh_token_hash", name="uq_user_sessions_refresh_hash"),
    )
    op.create_index(
        "ix_user_sessions_account_created", "user_sessions",
        ["application_id", "account_reference", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_user_sessions_account_created", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_constraint("fk_otp_challenges_authentication_grant", "otp_challenges", type_="foreignkey")
    op.drop_column("otp_challenges", "authentication_reference")
    op.drop_index("ix_authentication_grants_account_created", table_name="authentication_grants")
    op.drop_table("authentication_grants")
