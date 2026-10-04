"""Test 2: Exchange a password-login grant for a user access token.

Create an active account, authenticate by password, exchange the resulting
one-time authentication reference, and decode the RS256 JWT. The token should
identify as a user access token and report only `pwd` in its authentication
methods. Reusing the grant should be rejected. The AMR assertion currently
fails because password-only authentication is marked as OTP/MFA too.
"""

import jwt

from alzando_authorization import main as main_module
def test_password_login_issues_one_time_grant_and_password_only_amr(
    api, enable_services, create_test_account, login_user, issue_user_tokens, application_header
):
    """Password login yields a single-use grant and truthful AMR token claims."""
    client, sessions, settings = api
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)

    login_result = login_user(client)
    assert login_result["status"] == "AUTHENTICATED"
    authentication_reference = login_result["data"]["authentication_reference"]

    tokens = issue_user_tokens(client, authentication_reference)
    claims = jwt.decode(
        tokens["access_token"],
        main_module.token_service().public_key,
        algorithms=["RS256"],
        audience=settings.token_audience,
        issuer=settings.token_issuer,
    )
    assert claims["token_use"] == "user_access"
    assert claims["amr"] == ["pwd"]

    reused = client.post(
        "/api/v1/tokens",
        headers=application_header,
        json={"authentication_reference": authentication_reference},
    )
    assert reused.status_code == 400
    assert reused.json()["status"] == "INVALID_AUTHENTICATION_GRANT"
