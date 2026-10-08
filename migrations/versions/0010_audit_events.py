"""Add append-only audit events.

Revision ID: 0010_audit_events
Revises: 0009_user_sessions
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_audit_events"
down_revision = "0009_user_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("account_reference", sa.String(length=96), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_application_id_id", "audit_events", ["application_id", "id"])
    op.create_index(
        "ix_audit_events_application_type", "audit_events", ["application_id", "event_type", "id"]
    )
    op.create_index(
        "ix_audit_events_application_account", "audit_events", ["application_id", "account_reference", "id"]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_application_account", table_name="audit_events")
    op.drop_index("ix_audit_events_application_type", table_name="audit_events")
    op.drop_index("ix_audit_events_application_id_id", table_name="audit_events")
    op.drop_table("audit_events")
