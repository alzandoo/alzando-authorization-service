"""Configured SMTP is exercised by development flows without real network delivery."""

from alzando_authorization import main as main_module


def _configure_fake_smtp(settings):
    settings.smtp_host = "smtp.example.test"
    settings.smtp_port = 587
    settings.smtp_username = "smtp-user"
    settings.smtp_password = "smtp-password-test-only"
    settings.smtp_from_email = "verified-sender@example.test"
    settings.smtp_starttls = True


def test_development_signup_returns_code_and_queues_email_delivery(
    api, enable_services, application_header, password, monkeypatch
):
    client, _, settings = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION")
    _configure_fake_smtp(settings)
    sent = []
    monkeypatch.setattr(main_module, "send_configured_email", lambda **kwargs: sent.append(kwargs))

    response = client.post(
        "/api/v1/auth/signup",
        headers=application_header,
        json={"email": "smtp-signup@example.test", "password": password},
    )

    assert response.status_code == 201, response.text
    verification = response.json()["data"]["verification"]
    assert verification["development_only"] is True
    assert len(sent) == 1
    assert sent[0]["recipient"] == "smtp-signup@example.test"
    assert verification["code"] in sent[0]["body"]


def test_development_password_recovery_queues_configured_email(
    api, enable_services, create_test_account, application_header, monkeypatch
):
    client, sessions, settings = api
    enable_services("PASSWORD_RECOVERY")
    create_test_account(sessions)
    _configure_fake_smtp(settings)
    sent = []
    monkeypatch.setattr(main_module, "send_configured_email", lambda **kwargs: sent.append(kwargs))

    response = client.post(
        "/api/v1/auth/password/recovery",
        headers=application_header,
        json={"identifier": "user@example.com"},
    )

    assert response.status_code == 200, response.text
    recovery = response.json()["data"]
    assert recovery["development_only"] is True
    assert len(sent) == 1
    assert sent[0]["recipient"] == "user@example.com"
    assert recovery["verification_code"] in sent[0]["body"]


def test_development_email_otp_queues_configured_email(
    api, enable_services, create_test_account, application_header, monkeypatch
):
    client, sessions, settings = api
    enable_services("OTP", "EMAIL_VERIFICATION")
    create_test_account(sessions)
    _configure_fake_smtp(settings)
    sent = []
    monkeypatch.setattr(main_module, "send_configured_email", lambda **kwargs: sent.append(kwargs))

    response = client.post(
        "/api/v1/auth/otp/request",
        headers=application_header,
        json={
            "account_reference": "acct_pytest_user",
            "purpose": "VERIFICATION",
            "channel": "EMAIL",
        },
    )

    assert response.status_code == 200, response.text
    otp = response.json()["data"]
    assert otp["development_only"] is True
    assert len(sent) == 1
    assert sent[0]["recipient"] == "user@example.com"
    assert otp["otp"] in sent[0]["body"]
