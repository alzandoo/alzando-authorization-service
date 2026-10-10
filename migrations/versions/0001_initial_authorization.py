"""Create application-scoped RBAC tables.

Revision ID: 0001_initial_authorization
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial_authorization"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "roles",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("application_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "id", name="uq_roles_application_id_id"),
        sa.UniqueConstraint("application_id", "name", name="uq_roles_application_name"),
    )
    op.create_table(
        "permissions",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("application_id", sa.String(length=128), nullable=False),
        sa.Column("key", sa.String(length=150), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("resource", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "id", name="uq_permissions_application_id_id"),
        sa.UniqueConstraint("application_id", "key", name="uq_permissions_application_key"),
    )
    op.create_table(
        "role_permissions",
        sa.Column("application_id", sa.String(length=128), nullable=False),
        sa.Column("role_id", uuid_type, nullable=False),
        sa.Column("permission_id", uuid_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "role_id"], ["roles.application_id", "roles.id"],
            ondelete="CASCADE", name="fk_role_permissions_role",
        ),
        sa.ForeignKeyConstraint(
            ["application_id", "permission_id"], ["permissions.application_id", "permissions.id"],
            ondelete="CASCADE", name="fk_role_permissions_permission",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name="pk_role_permissions"),
    )
    op.create_table(
        "user_roles",
        sa.Column("application_id", sa.String(length=128), nullable=False),
        sa.Column("user_reference", sa.String(length=200), nullable=False),
        sa.Column("role_id", uuid_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id", "role_id"], ["roles.application_id", "roles.id"],
            ondelete="CASCADE", name="fk_user_roles_role",
        ),
        sa.PrimaryKeyConstraint("application_id", "user_reference", "role_id", name="pk_user_roles"),
    )
    op.create_index("ix_user_roles_application_user", "user_roles", ["application_id", "user_reference"])
    op.create_index("ix_role_permissions_application_role", "role_permissions", ["application_id", "role_id"])


def downgrade() -> None:
    op.drop_index("ix_role_permissions_application_role", table_name="role_permissions")
    op.drop_index("ix_user_roles_application_user", table_name="user_roles")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
