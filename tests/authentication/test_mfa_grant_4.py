"""Test 4: Require successful MFA before issuing application-user tokens.

Enable Login, Token, MFA, and OTP; authenticate an active account; and confirm
that its grant cannot be exchanged before MFA. Request an email OTP, verify
the development code, and confirm that the same grant can then be exchanged
for a user access token.
"""

import jwt

from alzando_authorization import main as main_module


def test_mfa_grant_requires_verified_challenge_before_token_issue(
    api, enable_services, create_test_account, issue_user_tokens, login_user, application_header
):
    """A login grant is gated on a valid MFA proof tied to that grant."""
    client, sessions, settings = api
    enable_services("LOGIN", "TOKEN", "MFA", "OTP")
    create_test_account(sessions)

    login_result = login_user(client)
    assert login_result["status"] == "MFA_REQUIRED"
    authentication_reference = login_result["data"]["authentication_reference"]

    blocked = client.post(
        "/api/v1/tokens",
        headers=application_header,
        json={"authentication_reference": authentication_reference},
    )
    assert blocked.status_code == 401
    assert blocked.json()["status"] == "MFA_REQUIRED"

    challenge = client.post(
        "/api/v1/auth/mfa/challenge",
        headers=application_header,
        json={"authentication_reference": authentication_reference, "channel": "EMAIL"},
    )
    assert challenge.status_code == 200, challenge.text
    challenge_data = challenge.json()["data"]

    generic_verification = client.post(
        "/api/v1/auth/otp/verify",
        headers=application_header,
        json={
            "challenge_reference": challenge_data["challenge_reference"],
            "otp": challenge_data["otp"],
        },
    )
    assert generic_verification.status_code == 400
    assert generic_verification.json()["status"] == "INVALID_OTP_CHALLENGE"

    verified = client.post(
        "/api/v1/auth/mfa/verify",
        headers=application_header,
        json={
            "challenge_reference": challenge_data["challenge_reference"],
            "otp": challenge_data["otp"],
        },
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["authentication_reference"] == authentication_reference
    tokens = issue_user_tokens(client, authentication_reference)
    assert tokens["access_token"]
    claims = jwt.decode(
        tokens["access_token"],
        main_module.token_service().public_key,
        algorithms=["RS256"],
        audience=settings.token_audience,
        issuer=settings.token_issuer,
    )
    assert claims["amr"] == ["pwd", "otp"]
