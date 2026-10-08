"""Functional Test Case F-MFA-01: MFA login and user-token journey.

Purpose
-------
Authenticate an account when MFA is required, demonstrate that the initial
login grant cannot issue tokens, complete an email OTP challenge, and exchange
the verified grant for user tokens.

Why this test matters
--------------------
The MFA flow ties a one-time challenge to a specific authentication grant.
This test demonstrates the required sequence and verifies that token issuance
is blocked until the challenge is successfully verified.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient. The test enables LOGIN, TOKEN, MFA, and OTP for its isolated
application and creates one active account. The development environment
returns an OTP in the challenge response; no external delivery provider is
needed.

Steps and expected outcomes
---------------------------
1. Log in; expect MFA_REQUIRED and an authentication reference.
2. Attempt token issuance before MFA; expect HTTP 401 MFA_REQUIRED.
3. Create an email MFA challenge and verify its OTP.
4. Exchange the verified grant for user tokens.

Logging
-------
Every HTTP call logs its description, expectations, and input/output.
Passwords, OTP values, and access/refresh tokens are redacted.
"""


def test_mfa_challenge_must_be_verified_before_user_token_issue(
    api, enable_services, create_test_account, http_request, password
):
    """Complete the MFA challenge required between password login and token issue."""
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN", "MFA", "OTP")
    create_test_account(sessions)
    headers = {"X-Dev-Application-Id": "app_pytest"}

    login = http_request(
        client,
        "POST",
        "/api/v1/auth/login",
        description="Authenticate the active account when MFA is enabled.",
        expectations="HTTP 200; status is MFA_REQUIRED and an authentication reference is returned.",
        json_body={"method": "PASSWORD", "identifier": "user@example.com", "password": password},
        headers=headers,
    )
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "MFA_REQUIRED"
    authentication_reference = login.json()["data"]["authentication_reference"]

    blocked_tokens = http_request(
        client,
        "POST",
        "/api/v1/tokens",
        description="Try to exchange the authentication grant before completing MFA.",
        expectations="HTTP 401 with MFA_REQUIRED; no user tokens are issued before the challenge is verified.",
        json_body={"authentication_reference": authentication_reference},
        headers=headers,
    )
    assert blocked_tokens.status_code == 401
    assert blocked_tokens.json()["status"] == "MFA_REQUIRED"

    challenge = http_request(
        client,
        "POST",
        "/api/v1/auth/mfa/challenge",
        description="Create an email OTP challenge bound to this authentication grant.",
        expectations="HTTP 200; an MFA challenge reference and development OTP are returned.",
        json_body={"authentication_reference": authentication_reference, "channel": "EMAIL"},
        headers=headers,
    )
    assert challenge.status_code == 200, challenge.text
    challenge_data = challenge.json()["data"]
    assert challenge_data["otp"]

    verified = http_request(
        client,
        "POST",
        "/api/v1/auth/mfa/verify",
        description="Verify the OTP for the MFA challenge and authentication grant.",
        expectations="HTTP 200; response confirms verification and returns the associated authentication reference.",
        json_body={
            "challenge_reference": challenge_data["challenge_reference"],
            "otp": challenge_data["otp"],
        },
        headers=headers,
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["authentication_reference"] == authentication_reference

    tokens = http_request(
        client,
        "POST",
        "/api/v1/tokens",
        description="Exchange the now MFA-verified authentication grant for user tokens.",
        expectations="HTTP 200; access and refresh tokens are issued for the authenticated user.",
        json_body={"authentication_reference": authentication_reference},
        headers=headers,
    )
    assert tokens.status_code == 200, tokens.text
    assert tokens.json()["status"] == "TOKENS_ISSUED"
    assert tokens.json()["data"]["access_token"]
    assert tokens.json()["data"]["refresh_token"]
