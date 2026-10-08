"""Functional Test Case F-OAUTH-01: OAuth client credentials and live service enforcement.

Purpose
-------
Register a confidential application, obtain an OAuth client-credentials
access token for its Login service, then disable Login and confirm the already
issued token can no longer call the protected Login API.

Why this test matters
--------------------
This follows the production client authentication pattern and verifies the
runtime service check. A token's scope grants a capability, while current
application service configuration can still disable that capability.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient. The test registers a confidential application through the
registry API. Its generated client credentials are used only in this isolated
test database.

Steps and expected outcomes
---------------------------
1. Register an application with Login enabled and obtain its client credentials.
2. Exchange the credentials for a token scoped to authentication:login.
3. Disable Login in the database after token issuance.
4. Call the Login API with the bearer token; expect SERVICE_NOT_ENABLED.

Logging
-------
Every HTTP call logs its description, expectations, and input/output. Basic
passwords, client secrets, access tokens, and bearer authorization headers are
redacted from the log.
"""


def test_oauth_client_token_respects_current_service_configuration(api, http_request):
    """An OAuth token cannot bypass a service disabled after token issuance."""
    client, sessions, _ = api

    registration = http_request(
        client,
        "POST",
        "/api/v1/applications",
        description="Register a confidential application with the Login service enabled.",
        expectations="HTTP 201; application and client credentials are created with authentication:login scope.",
        json_body={
            "name": "Functional OAuth Client",
            "description": "Created by F-OAUTH-01",
            "application_type": "EXTERNAL",
            "owner": {"organization": "Functional Test Suite"},
            "client_type": "CONFIDENTIAL",
            "configuration": {"enabled_services": ["LOGIN"]},
        },
        headers={"X-Dev-Application-Id": "alzando_platform"},
    )
    assert registration.status_code == 201, registration.text
    credentials = registration.json()["data"]["client"]
    application_id = registration.json()["data"]["application_id"]
    assert "authentication:login" in credentials["scopes"]

    token = http_request(
        client,
        "POST",
        "/oauth2/token",
        description="Authenticate the confidential client and request a Login-scoped access token.",
        expectations="HTTP 200; a bearer access token is returned with authentication:login scope.",
        data={"grant_type": "client_credentials", "scope": "authentication:login"},
        auth=(credentials["client_id"], credentials["client_secret"]),
    )
    assert token.status_code == 200, token.text
    assert token.json()["scope"] == "authentication:login"

    from alzando_authorization.models import ApplicationService

    with sessions() as db:
        login_service = db.get(ApplicationService, (application_id, "LOGIN"))
        assert login_service is not None
        login_service.enabled = False
        db.commit()

    blocked = http_request(
        client,
        "POST",
        "/api/v1/auth/login",
        description="Use the issued bearer token after Login has been disabled for the application.",
        expectations="HTTP 403 with SERVICE_NOT_ENABLED; the token scope cannot bypass current service configuration.",
        json_body={
            "method": "PASSWORD",
            "identifier": "nobody@example.com",
            "password": "not a real account password",
        },
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    assert blocked.status_code == 403, blocked.text
    assert blocked.json()["status"] == "SERVICE_NOT_ENABLED"
