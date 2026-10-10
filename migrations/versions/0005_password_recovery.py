"""Add password recovery challenges and explicit recovery lock state.

Revision ID: 0005_password_recovery
Revises: 0004_authentication_accounts
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_password_recovery"
down_revision = "0004_authentication_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "authentication_accounts",
        sa.Column("recovery_required", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(sa.text("""
        UPDATE authentication_accounts
        SET recovery_required = TRUE, status = 'ACTIVE'
        WHERE status = 'RECOVERY_REQUIRED'
    """))
    op.alter_column("authentication_accounts", "recovery_required", server_default=None)

    op.create_table(
        "password_recovery_challenges",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("recovery_reference", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=False),
        sa.Column("code_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_password_recovery_challenges_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "recovery_reference"),
    )
    op.create_index(
        "ix_password_recovery_challenges_account_created",
        "password_recovery_challenges", ["application_id", "account_reference", "created_at"],
    )


def downgrade() -> None:
    op.execute(sa.text("""
        UPDATE authentication_accounts
        SET status = 'RECOVERY_REQUIRED'
        WHERE recovery_required = TRUE
    """))
    op.drop_index(
        "ix_password_recovery_challenges_account_created", table_name="password_recovery_challenges"
    )
    op.drop_table("password_recovery_challenges")
    op.drop_column("authentication_accounts", "recovery_required")
