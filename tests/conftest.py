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
    monkeypatch.setattr(settings, "challenge_hmac_secret", "pytest-challenge-hmac-secret-32-bytes")
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

    service_codes = (
        "SIGNUP", "LOGIN", "PASSWORD_RECOVERY", "EMAIL_VERIFICATION", "PHONE_VERIFICATION",
        "OTP", "MFA", "TOKEN", "AUTHORIZATION",
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
        for code in service_codes:
            db.add(Service(
                service_code=code,
                name=code.replace("_", " ").title(),
                description=f"Pytest {code} service",
                service_type="AUTHENTICATION",
                status="ACTIVE",
            ))
        db.flush()
        for code in service_codes:
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
