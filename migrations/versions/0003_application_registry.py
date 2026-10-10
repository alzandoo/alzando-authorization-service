"""Add application registration and per-application service configuration.

Revision ID: 0003_application_registry
Revises: 0002_application_clients
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_application_registry"
down_revision = "0002_application_clients"
branch_labels = None
depends_on = None


SERVICES = [
    ("SIGNUP", "Signup", "Create an application-scoped authentication account.", "AUTHENTICATION"),
    ("LOGIN", "Login", "Authenticate an application user.", "AUTHENTICATION"),
    ("PASSWORD_RECOVERY", "Password Recovery", "Recover or reset an account password.", "AUTHENTICATION"),
    ("EMAIL_VERIFICATION", "Email Verification", "Verify an account email address.", "VERIFICATION"),
    ("PHONE_VERIFICATION", "Phone Verification", "Verify an account phone number.", "VERIFICATION"),
    ("OTP", "One-Time Password", "Issue and verify one-time passwords.", "AUTHENTICATION"),
    ("MFA", "Multi-Factor Authentication", "Apply configured multi-factor challenges.", "AUTHENTICATION"),
    ("PASSKEY", "Passkey", "Register and authenticate with passkeys.", "AUTHENTICATION"),
    ("SOCIAL_LOGIN", "Social Login", "Authenticate through a configured identity provider.", "AUTHENTICATION"),
    ("TOKEN", "Token Services", "Issue, refresh, and revoke application-user tokens.", "TOKEN"),
    ("AUTHORIZATION", "Authorization", "Manage RBAC configuration and evaluate permissions.", "AUTHORIZATION"),
    ("SECURITY", "Security Services", "Apply configured authentication security controls.", "SECURITY"),
    ("AUDIT", "Audit", "Record and retrieve security events.", "SECURITY"),
]


def upgrade() -> None:
    op.add_column(
        "application_clients",
        sa.Column("client_type", sa.String(length=24), nullable=False, server_default="CONFIDENTIAL"),
    )
    op.alter_column("application_clients", "client_secret_hash", existing_type=sa.String(length=256), nullable=True)

    op.create_table(
        "applications",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("application_type", sa.String(length=32), nullable=False),
        sa.Column("owner", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("application_id"),
    )
    op.create_table(
        "services",
        sa.Column("service_code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("service_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.PrimaryKeyConstraint("service_code"),
    )
    op.create_table(
        "application_services",
        sa.Column("application_id", sa.String(length=96), nullable=False),
        sa.Column("service_code", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.application_id"],
            ondelete="CASCADE", name="fk_application_services_application",
        ),
        sa.ForeignKeyConstraint(
            ["service_code"], ["services.service_code"],
            ondelete="RESTRICT", name="fk_application_services_service",
        ),
        sa.PrimaryKeyConstraint("application_id", "service_code"),
    )
    op.create_index("ix_application_services_service", "application_services", ["service_code"])

    service_table = sa.table(
        "services",
        sa.column("service_code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("service_type", sa.String),
        sa.column("status", sa.String),
    )
    op.bulk_insert(service_table, [
        {"service_code": code, "name": name, "description": description,
         "service_type": service_type, "status": "ACTIVE"}
        for code, name, description, service_type in SERVICES
    ])

    # Preserve existing development RBAC/client data as an active, authorization-enabled application.
    op.execute(sa.text("""
        INSERT INTO applications
            (application_id, name, application_type, owner, status, created_at, updated_at)
        SELECT legacy.application_id, legacy.application_id, 'EXTERNAL', CAST('{}' AS JSON),
               'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM (
            SELECT application_id FROM application_clients
            UNION SELECT application_id FROM roles
            UNION SELECT application_id FROM permissions
            UNION SELECT application_id FROM user_roles
        ) AS legacy
    """))
    op.execute(sa.text("""
        INSERT INTO application_services
            (application_id, service_code, enabled, configuration, created_at, updated_at)
        SELECT application_id, 'AUTHORIZATION', TRUE, CAST('{}' AS JSON),
               CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM applications
    """))


def downgrade() -> None:
    public_clients = op.get_bind().execute(sa.text(
        "SELECT count(*) FROM application_clients WHERE client_secret_hash IS NULL"
    )).scalar_one()
    if public_clients:
        raise RuntimeError("Cannot downgrade while public clients without secrets exist.")
    op.drop_index("ix_application_services_service", table_name="application_services")
    op.drop_table("application_services")
    op.drop_table("services")
    op.drop_table("applications")
    op.drop_column("application_clients", "client_type")
    op.alter_column("application_clients", "client_secret_hash", existing_type=sa.String(length=256), nullable=False)
