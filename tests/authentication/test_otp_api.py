from datetime import timedelta

from alzando_authorization.models import OtpChallenge, utc_now


def _request_otp(client, headers, account_reference="acct_pytest_user"):
    return client.post(
        "/api/v1/auth/otp/request", headers=headers,
        json={"account_reference": account_reference, "purpose": "VERIFICATION", "channel": "EMAIL"},
    )


def test_otp_verification_is_single_use_and_applies_resend_cooldown(
    api, enable_services, create_test_account, application_header
):
    client, sessions, _ = api
    enable_services("OTP", "EMAIL_VERIFICATION")
    create_test_account(sessions)

    requested = _request_otp(client, application_header)
    assert requested.status_code == 200, requested.text
    data = requested.json()["data"]
    assert data["purpose"] == "VERIFICATION"
    assert data["development_only"] is True

    resent = _request_otp(client, application_header)
    assert resent.status_code == 200
    assert resent.json()["data"]["challenge_reference"] == data["challenge_reference"]
    assert "otp" not in resent.json()["data"]

    verified = client.post(
        "/api/v1/auth/otp/verify", headers=application_header,
        json={"challenge_reference": data["challenge_reference"], "otp": data["otp"]},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["verified"] is True
    reused = client.post(
        "/api/v1/auth/otp/verify", headers=application_header,
        json={"challenge_reference": data["challenge_reference"], "otp": data["otp"]},
    )
    assert reused.status_code == 400
    limited = _request_otp(client, application_header)
    assert limited.status_code == 429
    assert limited.json()["status"] == "OTP_RATE_LIMITED"


def test_otp_rejects_wrong_code_and_expired_challenge(
    api, enable_services, create_test_account, application_header
):
    client, sessions, _ = api
    enable_services("OTP", "EMAIL_VERIFICATION")
    create_test_account(sessions)
    requested = _request_otp(client, application_header)
    data = requested.json()["data"]
    wrong_code = "000000" if data["otp"] != "000000" else "000001"
    wrong = client.post(
        "/api/v1/auth/otp/verify", headers=application_header,
        json={"challenge_reference": data["challenge_reference"], "otp": wrong_code},
    )
    assert wrong.status_code == 400
    with sessions() as db:
        challenge = db.get(OtpChallenge, ("app_pytest", data["challenge_reference"]))
        challenge.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    expired = client.post(
        "/api/v1/auth/otp/verify", headers=application_header,
        json={"challenge_reference": data["challenge_reference"], "otp": data["otp"]},
    )
    assert expired.status_code == 400
    assert expired.json()["status"] == "INVALID_OTP_CHALLENGE"


def test_otp_attempt_limit_locks_challenge(api, enable_services, create_test_account, application_header):
    client, sessions, _ = api
    enable_services("OTP", "EMAIL_VERIFICATION")
    create_test_account(sessions)
    data = _request_otp(client, application_header).json()["data"]
    wrong_code = "000000" if data["otp"] != "000000" else "000001"
    for _ in range(5):
        invalid = client.post(
            "/api/v1/auth/otp/verify", headers=application_header,
            json={"challenge_reference": data["challenge_reference"], "otp": wrong_code},
        )
        assert invalid.status_code == 400
    correct_after_lock = client.post(
        "/api/v1/auth/otp/verify", headers=application_header,
        json={"challenge_reference": data["challenge_reference"], "otp": data["otp"]},
    )
    assert correct_after_lock.status_code == 400
    with sessions() as db:
        challenge = db.get(OtpChallenge, ("app_pytest", data["challenge_reference"]))
        assert challenge.failed_attempts == 5
        assert challenge.used_at is not None


def test_otp_requires_matching_enabled_services_and_verified_channel(
    api, enable_services, create_test_account, application_header
):
    client, sessions, _ = api
    enable_services("OTP")
    create_test_account(sessions)
    missing_service = _request_otp(client, application_header)
    assert missing_service.status_code == 403
    assert missing_service.json()["status"] == "SERVICE_NOT_ENABLED"

    enable_services("EMAIL_VERIFICATION", "LOGIN")
    with sessions() as db:
        from alzando_authorization.models import AuthenticationAccount

        db.get(AuthenticationAccount, ("app_pytest", "acct_pytest_user")).email_verified = False
        db.commit()
    unverified = client.post(
        "/api/v1/auth/otp/request", headers=application_header,
        json={"account_reference": "acct_pytest_user", "purpose": "LOGIN", "channel": "EMAIL"},
    )
    assert unverified.status_code == 400
    assert unverified.json()["status"] == "OTP_CHANNEL_UNAVAILABLE"
