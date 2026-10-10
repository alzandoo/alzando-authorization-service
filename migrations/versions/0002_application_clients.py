"""Add confidential application clients for OAuth token issuance.

Revision ID: 0002_application_clients
Revises: 0001_initial_authorization
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_application_clients"
down_revision = "0001_initial_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "application_clients",
        sa.Column("client_id", sa.String(length=96), nullable=False),
        sa.Column("application_id", sa.String(length=128), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=256), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.create_index("ix_application_clients_application_id", "application_clients", ["application_id"])


def downgrade() -> None:
    op.drop_index("ix_application_clients_application_id", table_name="application_clients")
    op.drop_table("application_clients")
