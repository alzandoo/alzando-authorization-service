"""Test 5: Rotate refresh credentials and detect replay of an old token.

Authenticate an account, exchange its grant, and refresh the issued session.
The new refresh token must differ from the old token. Reusing the old token
must fail and revoke any still-active session for that account, so the newly
rotated refresh token must fail afterward as well.
"""


def test_refresh_rotation_and_replay_revokes_active_session(
    api, enable_services, create_test_account, issue_user_tokens, login_user, application_header
):
    """Refresh rotation prevents reuse and treats replay as session compromise."""
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)
    original = issue_user_tokens(client, login_user(client)["data"]["authentication_reference"])

    refreshed = client.post(
        "/api/v1/tokens/refresh",
        headers=application_header,
        json={"refresh_token": original["refresh_token"]},
    )
    assert refreshed.status_code == 200, refreshed.text
    replacement = refreshed.json()["data"]
    assert replacement["refresh_token"] != original["refresh_token"]

    replay = client.post(
        "/api/v1/tokens/refresh",
        headers=application_header,
        json={"refresh_token": original["refresh_token"]},
    )
    assert replay.status_code == 401
    assert replay.json()["status"] == "INVALID_REFRESH_TOKEN"

    after_replay = client.post(
        "/api/v1/tokens/refresh",
        headers=application_header,
        json={"refresh_token": replacement["refresh_token"]},
    )
    assert after_replay.status_code == 401
    assert after_replay.json()["status"] == "INVALID_REFRESH_TOKEN"
