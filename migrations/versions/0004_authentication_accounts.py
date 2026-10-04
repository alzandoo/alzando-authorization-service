"""Add application-scoped password authentication accounts.

Revision ID: 0004_authentication_accounts
Revises: 0003_application_registry
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_authentication_accounts"
down_revision = "0003_application_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authentication_accounts",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("phone", sa.String(length=32), nullable=True),
        sa.Column("display_name", sa.String(length=200), nullable=True),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.application_id"],
            ondelete="CASCADE", name="fk_authentication_accounts_application",
        ),
        sa.PrimaryKeyConstraint("application_id", "account_reference"),
        sa.UniqueConstraint(
            "application_id", "email", name="uq_authentication_accounts_application_email"
        ),
        sa.UniqueConstraint(
            "application_id", "phone", name="uq_authentication_accounts_application_phone"
        ),
    )
    op.create_index(
        "ix_authentication_accounts_application_status",
        "authentication_accounts", ["application_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_authentication_accounts_application_status", table_name="authentication_accounts")
    op.drop_table("authentication_accounts")
