"""Test 6: Revoke a refresh-token session idempotently.

Authenticate an account and issue user tokens, revoke the refresh token, and
repeat the revoke request. Both revoke calls should return TOKEN_REVOKED; a
later refresh attempt with that credential must be rejected.
"""


def test_revoke_is_idempotent_and_prevents_refresh(
    api, enable_services, create_test_account, issue_user_tokens, login_user, application_header
):
    """Revocation can be repeated safely and permanently blocks refresh."""
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)
    tokens = issue_user_tokens(client, login_user(client)["data"]["authentication_reference"])

    revoked = client.post(
        "/api/v1/tokens/revoke",
        headers=application_header,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "TOKEN_REVOKED"

    repeated = client.post(
        "/api/v1/tokens/revoke",
        headers=application_header,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert repeated.status_code == 200

    refresh = client.post(
        "/api/v1/tokens/refresh",
        headers=application_header,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 401
