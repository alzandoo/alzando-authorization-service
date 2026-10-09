"""Functional Test Case F-AUTH-01: User authentication and token lifecycle.

Purpose
-------
Exercise the complete password-based user journey: create an account, log in,
exchange the one-time authentication reference for user tokens, rotate the
refresh token, revoke the rotated session, and confirm it cannot be refreshed.

Why this test matters
--------------------
Applications use the authentication and token services together. This test
shows how service enablement gates API access and how a user session moves
from credentials to short-lived access tokens and revocable refresh tokens.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient. The test enables SIGNUP, LOGIN, and TOKEN for the isolated
``app_pytest`` application. No external email or SMS provider is needed.

Steps and expected outcomes
---------------------------
1. Sign up a user; expect an active account because verification services are
   disabled for this application.
2. Log in with the new credentials; expect a one-time authentication grant.
3. Exchange the grant for access and refresh tokens.
4. Refresh the session; expect a new access token and rotated refresh token.
5. Revoke the rotated refresh token; expect successful revocation.
6. Try to refresh with the revoked token; expect HTTP 401.

Logging
-------
Every HTTP call logs its API description, expectations, redacted input, and
response. Passwords and token values are redacted in both input and output.
"""


def test_signup_login_issue_refresh_and_revoke_user_tokens(api, enable_services, http_request):
    """Follow a newly registered user through token issue, rotation, and revoke."""
    client, _, _ = api
    enable_services("SIGNUP", "LOGIN", "TOKEN")
    headers = {"X-Dev-Application-Id": "app_pytest"}
    password = "functional test password 2026"

    signup_body = {
        "email": "functional.user@example.com",
        "display_name": "Functional User",
        "password": password,
    }
    signup = http_request(
        client,
        "POST",
        "/api/v1/auth/signup",
        description="Create a user account for the enabled application.",
        expectations="HTTP 201; an account reference is returned and status is ACCOUNT_CREATED.",
        json_body=signup_body,
        headers=headers,
    )
    assert signup.status_code == 201, signup.text
    assert signup.json()["status"] == "ACCOUNT_CREATED"
    account_reference = signup.json()["data"]["account_reference"]

    login_body = {
        "method": "PASSWORD",
        "identifier": signup_body["email"],
        "password": password,
    }
    login = http_request(
        client,
        "POST",
        "/api/v1/auth/login",
        description="Authenticate the newly created account with its email and password.",
        expectations="HTTP 200; status is AUTHENTICATED and a one-time authentication reference is returned.",
        json_body=login_body,
        headers=headers,
    )
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "AUTHENTICATED"
    assert login.json()["data"]["account_reference"] == account_reference
    authentication_reference = login.json()["data"]["authentication_reference"]

    issue = http_request(
        client,
        "POST",
        "/api/v1/tokens",
        description="Exchange the password authentication grant for user tokens.",
        expectations="HTTP 200; access and refresh tokens are issued.",
        json_body={"authentication_reference": authentication_reference},
        headers=headers,
    )
    assert issue.status_code == 200, issue.text
    assert issue.json()["status"] == "TOKENS_ISSUED"
    issued_tokens = issue.json()["data"]
    assert issued_tokens["access_token"]
    assert issued_tokens["refresh_token"]

    refresh = http_request(
        client,
        "POST",
        "/api/v1/tokens/refresh",
        description="Use the refresh token to renew the user session.",
        expectations="HTTP 200; a new access token and rotated refresh token are returned.",
        json_body={"refresh_token": issued_tokens["refresh_token"]},
        headers=headers,
    )
    assert refresh.status_code == 200, refresh.text
    assert refresh.json()["status"] == "TOKENS_REFRESHED"
    refreshed_tokens = refresh.json()["data"]

    # Verify that the refreshed access token works before revocation.
    me = http_request(
        client,
        "GET",
        "/api/v1/auth/me",
        description="Access the protected user endpoint with the current user access token.",
        expectations="HTTP 200; the authenticated account and session are returned.",
        headers={
            "Authorization": f"Bearer {refreshed_tokens['access_token']}"
        },
    )
    assert me.status_code == 200, me.text
    assert me.json()["status"] == "AUTHENTICATED_USER"
    assert (
        me.json()["data"]["account_reference"]
        == refreshed_tokens["account_reference"]
    )
    assert me.json()["data"]["session_id"] == refreshed_tokens["session_id"]

    assert refreshed_tokens["access_token"]
    assert refreshed_tokens["refresh_token"]
    assert refreshed_tokens["refresh_token"] != issued_tokens["refresh_token"]

    revoke = http_request(
        client,
        "POST",
        "/api/v1/tokens/revoke",
        description="Revoke the current session using its rotated refresh token.",
        expectations="HTTP 200; status is TOKEN_REVOKED and revoked is true.",
        json_body={"refresh_token": refreshed_tokens["refresh_token"]},
        headers=headers,
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["status"] == "TOKEN_REVOKED"
    assert revoke.json()["data"]["revoked"] is True

    # A revoked session must no longer accept its access token.
    access_after_revoke = http_request(
        client,
        "GET",
        "/api/v1/auth/me",
        description="Try to reuse the access token after its session has been revoked.",
        expectations="HTTP 401; a revoked session cannot access the protected user endpoint.",
        headers={
            "Authorization": f"Bearer {refreshed_tokens['access_token']}"
        },
    )
    assert access_after_revoke.status_code == 401, access_after_revoke.text
    assert access_after_revoke.json()["status"] == "UNAUTHENTICATED"


    refresh_revoked = http_request(
        client,
        "POST",
        "/api/v1/tokens/refresh",
        description="Attempt to refresh the session after its refresh token was revoked.",
        expectations="HTTP 401; the revoked refresh token cannot create a new session.",
        json_body={"refresh_token": refreshed_tokens["refresh_token"]},
        headers=headers,
    )
    assert refresh_revoked.status_code == 401, refresh_revoked.text
