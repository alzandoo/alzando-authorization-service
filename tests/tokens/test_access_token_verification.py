import jwt
import pytest

from alzando_authorization.config import Settings
from alzando_authorization.tokens import AccessTokenService


@pytest.fixture
def token_service():
    config = Settings(
        app_env="development",
        token_issuer="https://auth.example.test",
        token_audience="test-service",
        access_token_ttl_seconds=300,
    )
    return AccessTokenService(config)


def test_application_token_can_be_verified(token_service):
    token = token_service.issue(
        client_id="client_123",
        application_id="app_123",
        scopes=["read", "write"],
    )

    claims = token_service.verify(token)

    assert claims["client_id"] == "client_123"
    assert claims["application_id"] == "app_123"
    assert claims["scope"] == "read write"


def test_user_token_can_be_verified(token_service):
    token = token_service.issue_user(
        account_reference="acct_123",
        application_id="app_123",
        session_id="ses_123",
        mfa_authenticated=True,
    )

    claims = token_service.verify_user(token)

    assert claims["sub"] == "acct_123"
    assert claims["application_id"] == "app_123"
    assert claims["token_use"] == "user_access"
    assert claims["sid"] == "ses_123"
    assert claims["amr"] == ["pwd", "otp"]


def test_application_token_is_rejected_by_user_verifier(token_service):
    token = token_service.issue(
        client_id="client_123",
        application_id="app_123",
        scopes=["read"],
    )

    with pytest.raises(jwt.PyJWTError):
        token_service.verify_user(token)


def test_user_token_is_rejected_by_application_verifier(token_service):
    token = token_service.issue_user(
        account_reference="acct_123",
        application_id="app_123",
        session_id="ses_123",
        mfa_authenticated=False,
    )

    with pytest.raises(jwt.PyJWTError):
        token_service.verify(token)


def test_user_token_with_invalid_signature_is_rejected(token_service):
    token = token_service.issue_user(
        account_reference="acct_123",
        application_id="app_123",
        session_id="ses_123",
        mfa_authenticated=False,
    )

    tampered_token = token[:-1] + (
        "A" if token[-1] != "A" else "B"
    )

    with pytest.raises(jwt.PyJWTError):
        token_service.verify_user(tampered_token)
