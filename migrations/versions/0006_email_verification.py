"""Add email verification challenges.

Revision ID: 0006_email_verification
Revises: 0005_password_recovery
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_email_verification"
down_revision = "0005_password_recovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_verification_challenges",
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
            ondelete="CASCADE", name="fk_email_verification_challenges_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "verification_reference"),
    )
    op.create_index(
        "ix_email_verification_challenges_account_created",
        "email_verification_challenges", ["application_id", "account_reference", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_email_verification_challenges_account_created", table_name="email_verification_challenges"
    )
    op.drop_table("email_verification_challenges")
