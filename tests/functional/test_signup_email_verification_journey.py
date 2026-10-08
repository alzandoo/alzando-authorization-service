"""Functional Test Case F-VERIFY-01: Signup email-verification journey.

Purpose
-------
Register a user while email verification is enabled, confirm login remains at
the verification-required step, verify the email address, then authenticate
and issue user tokens.

Why this test matters
--------------------
Email verification prevents an unverified account from completing normal
authentication. This test follows the user from signup through the verification
gate and into a successful authenticated session.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient. The test enables SIGNUP, EMAIL_VERIFICATION, LOGIN, and
TOKEN for the isolated ``app_pytest`` application. In development mode the
verification code is returned in the API response, so no external email
provider is required.

Steps and expected outcomes
---------------------------
1. Sign up with a new email; expect VERIFICATION_REQUIRED.
2. Attempt login before verification; expect the account to remain at the
   verification-required state without an authentication reference.
3. Verify the email with the issued challenge code; expect verified=true.
4. Log in again; expect AUTHENTICATED and an authentication reference.
5. Exchange the grant for user tokens; expect access and refresh tokens.

Logging
-------
Every HTTP call logs its description, expectations, and input/output.
Passwords, verification codes, and tokens are redacted.
"""


def test_signup_verification_gate_then_login_and_issue_tokens(
    api, enable_services, http_request, password
):
    """Verify an email before allowing the account to obtain user tokens."""
    client, _, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION", "LOGIN", "TOKEN")
    headers = {"X-Dev-Application-Id": "app_pytest"}
    email = "verification.functional@example.com"

    signup = http_request(
        client,
        "POST",
        "/api/v1/auth/signup",
        description="Create a user account that requires email verification.",
        expectations="HTTP 201; status is VERIFICATION_REQUIRED and an email challenge is returned.",
        json_body={"email": email, "display_name": "Verification User", "password": password},
        headers=headers,
    )
    assert signup.status_code == 201, signup.text
    assert signup.json()["status"] == "VERIFICATION_REQUIRED"
    verification = signup.json()["data"]["verification"]
    assert verification["verification_reference"]
    assert verification["code"]

    before_verification = http_request(
        client,
        "POST",
        "/api/v1/auth/login",
        description="Attempt password login before verifying the email address.",
        expectations="HTTP 200; status remains VERIFICATION_REQUIRED and no authentication grant is issued.",
        json_body={"method": "PASSWORD", "identifier": email, "password": password},
        headers=headers,
    )
    assert before_verification.status_code == 200, before_verification.text
    assert before_verification.json()["status"] == "VERIFICATION_REQUIRED"
    assert "authentication_reference" not in before_verification.json()["data"]

    verified = http_request(
        client,
        "POST",
        "/api/v1/auth/verify/email",
        description="Submit the email challenge code to verify the new account's email address.",
        expectations="HTTP 200; response confirms the email address is verified.",
        json_body={
            "verification_reference": verification["verification_reference"],
            "code": verification["code"],
        },
        headers=headers,
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["verified"] is True

    login = http_request(
        client,
        "POST",
        "/api/v1/auth/login",
        description="Log in again after successful email verification.",
        expectations="HTTP 200; status is AUTHENTICATED and an authentication reference is returned.",
        json_body={"method": "PASSWORD", "identifier": email, "password": password},
        headers=headers,
    )
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "AUTHENTICATED"
    authentication_reference = login.json()["data"]["authentication_reference"]

    tokens = http_request(
        client,
        "POST",
        "/api/v1/tokens",
        description="Exchange the post-verification authentication grant for user tokens.",
        expectations="HTTP 200; access and refresh tokens are issued for the verified user.",
        json_body={"authentication_reference": authentication_reference},
        headers=headers,
    )
    assert tokens.status_code == 200, tokens.text
    assert tokens.json()["status"] == "TOKENS_ISSUED"
    assert tokens.json()["data"]["access_token"]
    assert tokens.json()["data"]["refresh_token"]
