from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from argon2 import PasswordHasher
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from alzando_authorization import main as main_module
from alzando_authorization.database import get_db
from alzando_authorization.models import Application, ApplicationService, AuthenticationAccount, Base, Service


APPLICATION_ID = "app_pytest"
APPLICATION_HEADER = {"X-Dev-Application-Id": APPLICATION_ID}
PASSWORD = "correct horse battery staple"


def create_account(sessions: sessionmaker[Session], email: str = "user@example.com") -> str:
    with sessions() as db:
        account = AuthenticationAccount(
            application_id=APPLICATION_ID,
            account_reference="acct_pytest_user",
            email=email,
            phone=None,
            display_name="Pytest User",
            password_hash=PasswordHasher().hash(PASSWORD),
            status="ACTIVE",
            email_verified=True,
            phone_verified=True,
            failed_login_attempts=0,
            recovery_required=False,
        )
        db.add(account)
        db.commit()
        return account.account_reference


def login(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        headers=APPLICATION_HEADER,
        json={"method": "PASSWORD", "identifier": "user@example.com", "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()


def issue_tokens(client: TestClient, authentication_reference: str) -> dict:
    response = client.post(
        "/api/v1/tokens",
        headers=APPLICATION_HEADER,
        json={"authentication_reference": authentication_reference},
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]


@pytest.fixture
def application_header() -> dict[str, str]:
    return APPLICATION_HEADER


@pytest.fixture
def password() -> str:
    return PASSWORD


@pytest.fixture
def create_test_account():
    return create_account


@pytest.fixture
def login_user():
    return login


@pytest.fixture
def issue_user_tokens():
    return issue_tokens


class SQLiteTestSession(Session):
    """Restore timezone awareness lost by SQLite's DateTime implementation."""


@event.listens_for(SQLiteTestSession, "loaded_as_persistent")
def _normalize_sqlite_datetimes(_session, instance) -> None:
    for name, value in vars(instance).items():
        if isinstance(value, datetime) and value.tzinfo is None:
            setattr(instance, name, value.replace(tzinfo=timezone.utc))


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Generator[tuple[TestClient, sessionmaker[Session], object], None, None]:
    settings = main_module.settings
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "allow_dev_identity_header", True)
    monkeypatch.setattr(settings, "challenge_hmac_secret", "pytest-challenge-hmac-secret-32-bytes")
    # Keep tests hermetic even when a developer has real provider credentials in .env.
    monkeypatch.setattr(settings, "smtp_host", None)
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_username", None)
    monkeypatch.setattr(settings, "smtp_password", None)
    monkeypatch.setattr(settings, "smtp_from_email", None)
    monkeypatch.setattr(settings, "smtp_starttls", True)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_ip_per_minute", 120)
    monkeypatch.setattr(settings, "rate_limit_identifier_attempts", 10)
    monkeypatch.setattr(settings, "rate_limit_identifier_window_seconds", 900)
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    monkeypatch.setattr(settings, "verification_resend_interval_seconds", 60)
    main_module.token_service.cache_clear()

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False, class_=SQLiteTestSession
    )

    # Match the production catalogue seeded by migration 0003_application_registry.
    # The test database is intentionally isolated, but uses the same service
    # codes, names, descriptions, types, and active status as production.
    production_service_catalogue = (
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
    )
    with sessions() as db:
        db.add(Application(
            application_id="app_pytest",
            name="Pytest Application",
            application_type="EXTERNAL",
            owner={},
            status="ACTIVE",
        ))
        db.flush()
        for code, name, description, service_type in production_service_catalogue:
            db.add(Service(
                service_code=code,
                name=name,
                description=description,
                service_type=service_type,
                status="ACTIVE",
            ))
        db.flush()
        for code, _name, _description, _service_type in production_service_catalogue:
            db.add(ApplicationService(
                application_id="app_pytest",
                service_code=code,
                enabled=False,
                configuration={},
            ))
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        with sessions() as db:
            yield db

    app = main_module.create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client, sessions, settings

    app.dependency_overrides.clear()
    engine.dispose()
    main_module.token_service.cache_clear()


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture
def enable_services(api):
    _, sessions, _ = api

    def enable(*service_codes: str) -> None:
        with sessions() as db:
            for code in service_codes:
                service = db.get(ApplicationService, ("app_pytest", code))
                assert service is not None
                service.enabled = True
            db.commit()

    return enable
