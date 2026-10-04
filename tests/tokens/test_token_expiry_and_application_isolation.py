from datetime import timedelta

from alzando_authorization.models import (
    Application,
    ApplicationService,
    AuthenticationGrant,
    UserSession,
    utc_now,
)


def _add_second_application(sessions):
    with sessions() as db:
        db.add(Application(
            application_id="app_other",
            name="Other Application",
            application_type="EXTERNAL",
            owner={},
            status="ACTIVE",
        ))
        db.flush()
        db.add_all([
            ApplicationService(
                application_id="app_other", service_code="LOGIN", enabled=True, configuration={}
            ),
            ApplicationService(
                application_id="app_other", service_code="TOKEN", enabled=True, configuration={}
            ),
        ])
        db.commit()


def test_expired_authentication_grant_cannot_issue_user_tokens(
    api, enable_services, create_test_account, login_user, application_header
):
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)
    authentication_reference = login_user(client)["data"]["authentication_reference"]
    with sessions() as db:
        grant = db.get(AuthenticationGrant, ("app_pytest", authentication_reference))
        grant.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()

    response = client.post(
        "/api/v1/tokens", headers=application_header,
        json={"authentication_reference": authentication_reference},
    )
    assert response.status_code == 400
    assert response.json()["status"] == "INVALID_AUTHENTICATION_GRANT"


def test_expired_refresh_token_is_rejected(
    api, enable_services, create_test_account, login_user, issue_user_tokens, application_header
):
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)
    tokens = issue_user_tokens(client, login_user(client)["data"]["authentication_reference"])
    with sessions() as db:
        session = db.get(UserSession, ("app_pytest", tokens["session_id"]))
        session.refresh_expires_at = utc_now() - timedelta(seconds=1)
        db.commit()

    response = client.post(
        "/api/v1/tokens/refresh", headers=application_header,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 401
    assert response.json()["status"] == "INVALID_REFRESH_TOKEN"


def test_authentication_grants_and_refresh_tokens_are_application_scoped(
    api, enable_services, create_test_account, login_user, issue_user_tokens
):
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)
    _add_second_application(sessions)
    authentication_reference = login_user(client)["data"]["authentication_reference"]
    token_attempt = client.post(
        "/api/v1/tokens", headers={"X-Dev-Application-Id": "app_other"},
        json={"authentication_reference": authentication_reference},
    )
    assert token_attempt.status_code == 400
    assert token_attempt.json()["status"] == "INVALID_AUTHENTICATION_GRANT"

    tokens = issue_user_tokens(client, authentication_reference)
    refresh_attempt = client.post(
        "/api/v1/tokens/refresh", headers={"X-Dev-Application-Id": "app_other"},
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh_attempt.status_code == 401
    assert refresh_attempt.json()["status"] == "INVALID_REFRESH_TOKEN"
