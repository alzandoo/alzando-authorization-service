"""Integration test: apply the full Alembic history to disposable PostgreSQL."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SERVICE_CODES = {
    "SIGNUP",
    "LOGIN",
    "PASSWORD_RECOVERY",
    "EMAIL_VERIFICATION",
    "PHONE_VERIFICATION",
    "OTP",
    "MFA",
    "PASSKEY",
    "SOCIAL_LOGIN",
    "TOKEN",
    "AUTHORIZATION",
    "SECURITY",
    "AUDIT",
}


@pytest.mark.integration
def test_postgres_migration_creates_schema_and_service_catalogue(monkeypatch):
    """Verify PostgreSQL can apply all revisions and receives the service seed."""
    admin_url_text = os.getenv("POSTGRES_TEST_ADMIN_URL")
    if not admin_url_text:
        pytest.skip("Set POSTGRES_TEST_ADMIN_URL to an admin connection for disposable PostgreSQL tests.")

    admin_url = make_url(admin_url_text)
    database_name = f"authz_mig_{uuid4().hex}"
    test_url = admin_url.set(database=database_name)
    quoted_database_name = f'"{database_name}"'  # Generated from a fixed prefix and hexadecimal UUID.
    admin_engine = create_engine(admin_url)
    created = False

    try:
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            connection.exec_driver_sql(f"CREATE DATABASE {quoted_database_name}")
        created = True

        monkeypatch.setenv("DATABASE_URL", test_url.render_as_string(hide_password=False))
        alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
        command.upgrade(alembic_config, "head")

        test_engine = create_engine(test_url)
        try:
            with test_engine.connect() as connection:
                revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
                service_rows = connection.execute(text(
                    "SELECT service_code, status FROM services"
                )).all()
                application_tables = connection.execute(text("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = current_schema()
                """)).scalars().all()
        finally:
            test_engine.dispose()

        assert revision == "0009_user_sessions"
        assert {code for code, _status in service_rows} == EXPECTED_SERVICE_CODES
        assert all(status == "ACTIVE" for _code, status in service_rows)
        assert {
            "applications",
            "services",
            "application_services",
            "authentication_accounts",
            "user_sessions",
        } <= set(application_tables)
    finally:
        if created:
            with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                connection.execute(text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                ), {"database_name": database_name})
                connection.exec_driver_sql(f"DROP DATABASE IF EXISTS {quoted_database_name}")
        admin_engine.dispose()
