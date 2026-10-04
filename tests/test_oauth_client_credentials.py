import pytest

from alzando_authorization import main as main_module
from alzando_authorization.clients import create_confidential_client
from alzando_authorization.models import ApplicationService


def _create_client(sessions, scopes=("authentication:login",)):
    with sessions() as db:
        client_id, secret = create_confidential_client(db, "app_pytest", list(scopes))
        return client_id, secret


def _enable(sessions, service_code):
    with sessions() as db:
        service = db.get(ApplicationService, ("app_pytest", service_code))
        service.enabled = True
        db.commit()


def test_client_credentials_issues_scoped_token(api):
    client, sessions, settings = api
    _enable(sessions, "LOGIN")
    client_id, secret = _create_client(sessions)
    response = client.post(
        "/oauth2/token",
        auth=(client_id, secret),
        data={"grant_type": "client_credentials", "scope": "authentication:login"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["scope"] == "authentication:login"
    claims = main_module.token_service().verify(response.json()["access_token"])
    assert claims["client_id"] == client_id
    assert claims["application_id"] == "app_pytest"
    assert claims["scope"] == "authentication:login"
    assert claims["iss"] == settings.token_issuer


@pytest.mark.parametrize(
    ("auth", "form", "expected_error", "expected_status"),
    [
        (None, {"grant_type": "client_credentials"}, "invalid_client", 401),
        (("client_missing", "wrong"), {"grant_type": "client_credentials"}, "invalid_client", 401),
        (("unused", "unused"), {"grant_type": "password"}, "unsupported_grant_type", 400),
    ],
)
def test_client_credentials_rejects_missing_or_invalid_auth(api, auth, form, expected_error, expected_status):
    client, _, _ = api
    response = client.post("/oauth2/token", auth=auth, data=form)
    assert response.status_code == expected_status
    assert response.json()["error"] == expected_error


def test_client_credentials_rejects_ungranted_or_disabled_scope(api):
    client, sessions, _ = api
    client_id, secret = _create_client(sessions)
    ungranted = client.post(
        "/oauth2/token", auth=(client_id, secret),
        data={"grant_type": "client_credentials", "scope": "authorization:check"},
    )
    assert ungranted.status_code == 400
    assert ungranted.json()["error"] == "invalid_scope"

    disabled = client.post(
        "/oauth2/token", auth=(client_id, secret),
        data={"grant_type": "client_credentials", "scope": "authentication:login"},
    )
    assert disabled.status_code == 400
    assert disabled.json()["error"] == "invalid_scope"


def test_client_credentials_cannot_use_inactive_client(api):
    client, sessions, _ = api
    _enable(sessions, "LOGIN")
    client_id, secret = _create_client(sessions)
    with sessions() as db:
        from alzando_authorization.models import ApplicationClient

        db.get(ApplicationClient, client_id).is_active = False
        db.commit()
    response = client.post(
        "/oauth2/token", auth=(client_id, secret),
        data={"grant_type": "client_credentials"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_api_scope_is_checked_again_after_token_issuance(api):
    client, sessions, _ = api
    _enable(sessions, "LOGIN")
    client_id, secret = _create_client(sessions)
    token_response = client.post(
        "/oauth2/token", auth=(client_id, secret),
        data={"grant_type": "client_credentials", "scope": "authentication:login"},
    )
    assert token_response.status_code == 200
    with sessions() as db:
        db.get(ApplicationService, ("app_pytest", "LOGIN")).enabled = False
        db.commit()

    response = client.post(
        "/api/v1/auth/login",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
        json={"identifier": "missing@example.com", "password": "wrong"},
    )
    assert response.status_code == 403
    assert response.json()["status"] == "SERVICE_NOT_ENABLED"
