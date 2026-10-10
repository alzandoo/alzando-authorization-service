from datetime import timedelta

from argon2 import PasswordHasher

from alzando_authorization.models import (
    AuthenticationAccount,
    EmailVerificationChallenge,
    PasswordRecoveryChallenge,
    PhoneVerificationChallenge,
    utc_now,
)


def test_password_recovery_reset_clears_lockout_and_is_single_use(
    api, enable_services, create_test_account, application_header, password
):
    client, sessions, _ = api
    enable_services("LOGIN", "TOKEN", "PASSWORD_RECOVERY")
    create_test_account(sessions)
    with sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", "acct_pytest_user"))
        account.failed_login_attempts = 3
        account.recovery_required = True
        db.commit()

    recovery = client.post(
        "/api/v1/auth/password/recovery", headers=application_header,
        json={"identifier": " USER@example.com "},
    )
    assert recovery.status_code == 200
    assert recovery.json()["status"] == "RECOVERY_INITIATED"
    details = recovery.json()["data"]
    reset = client.post(
        "/api/v1/auth/password/reset", headers=application_header,
        json={
            "recovery_reference": details["recovery_reference"],
            "verification_code": details["verification_code"],
            "new_password": "a newer correct password",
        },
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["data"]["authentication_state"] == "READY"
    repeated = client.post(
        "/api/v1/auth/password/reset", headers=application_header,
        json={
            "recovery_reference": details["recovery_reference"],
            "verification_code": details["verification_code"],
            "new_password": "another newer password",
        },
    )
    assert repeated.status_code == 400
    assert repeated.json()["status"] == "INVALID_RECOVERY_CHALLENGE"

    login = client.post(
        "/api/v1/auth/login", headers=application_header,
        json={"identifier": "user@example.com", "password": "a newer correct password"},
    )
    assert login.status_code == 200, login.text
    with sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", "acct_pytest_user"))
        assert account.recovery_required is False
        assert account.failed_login_attempts == 0
        assert PasswordHasher().verify(account.password_hash, "a newer correct password")


def test_password_recovery_does_not_reveal_unknown_accounts(api, enable_services, application_header):
    client, _, _ = api
    enable_services("PASSWORD_RECOVERY")
    known = client.post(
        "/api/v1/auth/password/recovery", headers=application_header,
        json={"identifier": "missing@example.com"},
    )
    assert known.status_code == 200
    assert known.json()["status"] == "RECOVERY_INITIATED"
    assert "recovery_reference" not in known.json()["data"]


def test_password_recovery_resend_cooldown_and_attempt_limit(
    api, enable_services, create_test_account, application_header
):
    client, sessions, _ = api
    enable_services("PASSWORD_RECOVERY")
    create_test_account(sessions)
    first = client.post(
        "/api/v1/auth/password/recovery", headers=application_header,
        json={"identifier": "user@example.com"},
    ).json()["data"]
    second = client.post(
        "/api/v1/auth/password/recovery", headers=application_header,
        json={"identifier": "user@example.com"},
    ).json()["data"]
    assert "recovery_reference" in first
    assert "recovery_reference" not in second

    wrong_code = "000000" if first["verification_code"] != "000000" else "000001"
    for _ in range(5):
        wrong = client.post(
            "/api/v1/auth/password/reset", headers=application_header,
            json={"recovery_reference": first["recovery_reference"],
                  "verification_code": wrong_code, "new_password": "replacement password"},
        )
        assert wrong.status_code == 400
    correct_after_lock = client.post(
        "/api/v1/auth/password/reset", headers=application_header,
        json={"recovery_reference": first["recovery_reference"],
              "verification_code": first["verification_code"], "new_password": "replacement password"},
    )
    assert correct_after_lock.status_code == 400
    with sessions() as db:
        challenge = db.get(PasswordRecoveryChallenge, ("app_pytest", first["recovery_reference"]))
        assert challenge.failed_attempts == 5
        assert challenge.used_at is not None


def test_expired_password_recovery_challenge_is_rejected(
    api, enable_services, create_test_account, application_header
):
    client, sessions, _ = api
    enable_services("PASSWORD_RECOVERY")
    create_test_account(sessions)
    data = client.post(
        "/api/v1/auth/password/recovery", headers=application_header,
        json={"identifier": "user@example.com"},
    ).json()["data"]
    with sessions() as db:
        challenge = db.get(PasswordRecoveryChallenge, ("app_pytest", data["recovery_reference"]))
        challenge.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    response = client.post(
        "/api/v1/auth/password/reset", headers=application_header,
        json={"recovery_reference": data["recovery_reference"],
              "verification_code": data["verification_code"], "new_password": "replacement password"},
    )
    assert response.status_code == 400
    assert response.json()["status"] == "INVALID_RECOVERY_CHALLENGE"


def test_email_verification_activates_account_and_rejects_reuse(
    api, enable_services, application_header, password
):
    client, sessions, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION", "LOGIN", "TOKEN")
    signup = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": " New.User@example.com ", "password": password},
    )
    assert signup.status_code == 201, signup.text
    challenge = signup.json()["data"]["verification"]
    assert challenge["code"]
    with sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", signup.json()["data"]["account_reference"]))
        assert account.email == "new.user@example.com"
        assert account.status == "PENDING_VERIFICATION"

    verified = client.post(
        "/api/v1/auth/verify/email", headers=application_header,
        json={"verification_reference": challenge["verification_reference"], "code": "000000"},
    )
    if challenge["code"] == "000000":
        assert verified.status_code == 200
    else:
        assert verified.status_code == 400
        verified = client.post(
            "/api/v1/auth/verify/email", headers=application_header,
            json={"verification_reference": challenge["verification_reference"], "code": challenge["code"]},
        )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["verified"] is True
    reused = client.post(
        "/api/v1/auth/verify/email", headers=application_header,
        json={"verification_reference": challenge["verification_reference"], "code": challenge["code"]},
    )
    assert reused.status_code == 400
    login = client.post(
        "/api/v1/auth/login", headers=application_header,
        json={"identifier": "new.user@example.com", "password": password},
    )
    assert login.status_code == 200
    assert login.json()["status"] == "AUTHENTICATED"


def test_phone_verification_requires_e164_and_completes_channel(
    api, enable_services, application_header, password
):
    client, sessions, _ = api
    enable_services("SIGNUP", "PHONE_VERIFICATION")
    invalid = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "bad-phone@example.com", "phone": "555-1212", "password": password},
    )
    assert invalid.status_code == 422

    signup = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "phone-user@example.com", "phone": "+14155550123", "password": password},
    )
    assert signup.status_code == 201, signup.text
    data = signup.json()["data"]
    challenge = data["phone_verification"]
    assert signup.json()["status"] == "VERIFICATION_REQUIRED"
    verified = client.post(
        "/api/v1/auth/verify/phone", headers=application_header,
        json={"verification_reference": challenge["verification_reference"], "code": challenge["code"]},
    )
    assert verified.status_code == 200, verified.text
    with sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", data["account_reference"]))
        assert account.phone_verified is True
        assert account.status == "ACTIVE"


def test_verification_challenges_enforce_attempt_limits_and_expiry(
    api, enable_services, application_header, password
):
    client, sessions, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION", "PHONE_VERIFICATION")
    email_signup = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "limited-email@example.com", "phone": "+14155550125", "password": password},
    )
    email_challenge = email_signup.json()["data"]["verification"]
    with sessions() as db:
        challenge = db.get(
            EmailVerificationChallenge, ("app_pytest", email_challenge["verification_reference"])
        )
        challenge.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    expired_email = client.post(
        "/api/v1/auth/verify/email", headers=application_header,
        json={"verification_reference": email_challenge["verification_reference"],
              "code": email_challenge["code"]},
    )
    assert expired_email.status_code == 400
    assert expired_email.json()["status"] == "INVALID_VERIFICATION_CHALLENGE"

    phone_signup = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "limited-phone@example.com", "phone": "+14155550124", "password": password},
    )
    phone_challenge = phone_signup.json()["data"]["phone_verification"]
    wrong_code = "000000" if phone_challenge["code"] != "000000" else "000001"
    for _ in range(5):
        invalid = client.post(
            "/api/v1/auth/verify/phone", headers=application_header,
            json={"verification_reference": phone_challenge["verification_reference"], "code": wrong_code},
        )
        assert invalid.status_code == 400
    correct_after_lock = client.post(
        "/api/v1/auth/verify/phone", headers=application_header,
        json={"verification_reference": phone_challenge["verification_reference"],
              "code": phone_challenge["code"]},
    )
    assert correct_after_lock.status_code == 400
    with sessions() as db:
        challenge = db.get(
            PhoneVerificationChallenge, ("app_pytest", phone_challenge["verification_reference"])
        )
        assert challenge.failed_attempts == 5
        assert challenge.used_at is not None


def test_authentication_is_application_scoped_and_requires_enabled_service(
    api, enable_services, create_test_account
):
    client, sessions, _ = api
    from alzando_authorization.models import Application, ApplicationService

    with sessions() as db:
        db.add(Application(
            application_id="app_other", name="Other", application_type="EXTERNAL", owner={}, status="ACTIVE"
        ))
        db.flush()
        db.add_all([
            ApplicationService(
                application_id="app_other", service_code="LOGIN", enabled=True, configuration={}
            ),
            ApplicationService(
                application_id="app_other", service_code="TOKEN", enabled=True, configuration={}
            ),
        ])
        db.commit()
    enable_services("LOGIN", "TOKEN")
    create_test_account(sessions)

    response = client.post(
        "/api/v1/auth/login", headers={"X-Dev-Application-Id": "app_other"},
        json={"identifier": "user@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 401
    assert response.json()["status"] == "AUTHENTICATION_FAILED"

    disabled = client.post(
        "/api/v1/auth/signup", headers={"X-Dev-Application-Id": "app_pytest"},
        json={"email": "blocked@example.com", "password": "correct horse battery staple"},
    )
    assert disabled.status_code == 403
    assert disabled.json()["status"] == "SERVICE_NOT_ENABLED"


def test_signup_rejects_duplicate_accounts_and_requires_phone_when_enabled(
    api, enable_services, create_test_account, application_header, password
):
    client, sessions, _ = api
    enable_services("SIGNUP", "PHONE_VERIFICATION")
    create_test_account(sessions)
    missing_phone = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "new-phone@example.com", "password": password},
    )
    duplicate = client.post(
        "/api/v1/auth/signup", headers=application_header,
        json={"email": "USER@example.com", "phone": "+14155550126", "password": password},
    )
    assert missing_phone.status_code == 422
    assert missing_phone.json()["status"] == "PHONE_REQUIRED"
    assert duplicate.status_code == 409
    assert duplicate.json()["status"] == "ACCOUNT_ALREADY_EXISTS"
