"""Test 3: Lock an account after three incorrect password attempts.

Create an active account, submit three incorrect passwords, and verify the
first two return AUTHENTICATION_FAILED while the third transitions the account
to RECOVERY_REQUIRED. A later attempt with the correct password must remain
blocked until the account completes password recovery.
"""


def test_three_bad_passwords_require_recovery(
    api, enable_services, create_test_account, application_header, password
):
    """Repeated bad credentials lock login and require password recovery."""
    client, sessions, _ = api
    enable_services("LOGIN")
    create_test_account(sessions)

    statuses = []
    for _ in range(3):
        response = client.post(
            "/api/v1/auth/login",
            headers=application_header,
            json={"identifier": "user@example.com", "password": "wrong password"},
        )
        statuses.append(response.json()["status"])

    assert statuses == ["AUTHENTICATION_FAILED", "AUTHENTICATION_FAILED", "RECOVERY_REQUIRED"]

    locked = client.post(
        "/api/v1/auth/login",
        headers=application_header,
        json={"identifier": "user@example.com", "password": password},
    )
    assert locked.status_code == 401
    assert locked.json()["status"] == "RECOVERY_REQUIRED"
