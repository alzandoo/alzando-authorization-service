"""Add purpose-scoped OTP challenges.

Revision ID: 0008_otp_challenges
Revises: 0007_phone_verification
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_otp_challenges"
down_revision = "0007_phone_verification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "otp_challenges",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("challenge_reference", sa.String(length=96), nullable=False),
        sa.Column("subject_reference", sa.String(length=96), nullable=False),
        sa.Column("account_reference", sa.String(length=96), nullable=True),
        sa.Column("purpose", sa.String(length=24), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("code_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "account_reference"],
            ["authentication_accounts.application_id", "authentication_accounts.account_reference"],
            ondelete="CASCADE", name="fk_otp_challenges_account",
        ),
        sa.PrimaryKeyConstraint("application_id", "challenge_reference"),
    )
    op.create_index(
        "ix_otp_challenges_subject_created", "otp_challenges",
        ["application_id", "subject_reference", "purpose", "channel", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_otp_challenges_subject_created", table_name="otp_challenges")
    op.drop_table("otp_challenges")
