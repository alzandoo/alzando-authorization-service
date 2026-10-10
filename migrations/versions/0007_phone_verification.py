"""Add phone verification state and challenges.

Revision ID: 0007_phone_verification
Revises: 0006_email_verification
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_phone_verification"
down_revision = "0006_email_verification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "authentication_accounts",
        sa.Column("phone_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.alter_column("authentication_accounts", "phone_verified", server_default=None)

    op.create_table(
        "phone_verification_challenges",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("verification_reference", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=False),
        sa.Column("code_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_phone_verification_challenges_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "verification_reference"),
    )
    op.create_index(
        "ix_phone_verification_challenges_account_created",
        "phone_verification_challenges", ["application_id", "account_reference", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phone_verification_challenges_account_created", table_name="phone_verification_challenges"
    )
    op.drop_table("phone_verification_challenges")
    op.drop_column("authentication_accounts", "phone_verified")
