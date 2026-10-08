"""Coverage for verification resend, rate limits, session invalidation, and audit events."""

from datetime import timedelta

import pytest

from alzando_authorization.models import (
    AuditEvent,
    AuthenticationAccount,
    EmailVerificationChallenge,
    PhoneVerificationChallenge,
    UserSession,
    utc_now,
)


PLATFORM_HEADER = {"X-Dev-Application-Id": "alzando_platform"}


def _login(client, headers, identifier="user@example.com", password="wrong password"):
    return client.post(
        "/api/v1/auth/login",
        headers=headers,
        json={"identifier": identifier, "password": password},
    )


def test_expired_email_verification_can_be_resent_and_used(
    api, enable_services, application_header, password
):
    client, db_sessions, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION")
    signup = client.post(
        "/api/v1/auth/signup",
        headers=application_header,
        json={"email": "resend-email@example.com", "password": password},
    )
    assert signup.status_code == 201, signup.text
    account_reference = signup.json()["data"]["account_reference"]
    original = signup.json()["data"]["verification"]

    with db_sessions() as db:
        challenge = db.get(EmailVerificationChallenge, ("app_pytest", original["verification_reference"]))
        challenge.created_at = utc_now() - timedelta(minutes=2)
        challenge.expires_at = utc_now() - timedelta(minutes=1)
        db.commit()

    resent = client.post(
        "/api/v1/auth/verify/email/resend",
        headers=application_header,
        json={"account_reference": account_reference},
    )
    assert resent.status_code == 200, resent.text
    new_challenge = resent.json()["data"]
    assert new_challenge["channel"] == "EMAIL"
    assert new_challenge["verification_reference"] != original["verification_reference"]
    assert new_challenge["development_only"] is True

    old_code = client.post(
        "/api/v1/auth/verify/email",
        headers=application_header,
        json={"verification_reference": original["verification_reference"], "code": original["code"]},
    )
    assert old_code.status_code == 400

    verified = client.post(
        "/api/v1/auth/verify/email",
        headers=application_header,
        json={
            "verification_reference": new_challenge["verification_reference"],
            "code": new_challenge["code"],
        },
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["verified"] is True
    with db_sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", account_reference))
        assert account.status == "ACTIVE"
        assert account.email_verified is True


def test_email_verification_resend_cooldown_and_verified_account_rejection(
    api, enable_services, application_header, password, create_test_account
):
    client, db_sessions, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION")
    signup = client.post(
        "/api/v1/auth/signup",
        headers=application_header,
        json={"email": "cooldown@example.com", "password": password},
    )
    account_reference = signup.json()["data"]["account_reference"]

    too_soon = client.post(
        "/api/v1/auth/verify/email/resend",
        headers=application_header,
        json={"account_reference": account_reference},
    )
    assert too_soon.status_code == 429
    assert too_soon.json()["status"] == "VERIFICATION_RATE_LIMITED"
    assert int(too_soon.headers["Retry-After"]) >= 1

    create_test_account(db_sessions)
    verified_account = client.post(
        "/api/v1/auth/verify/email/resend",
        headers=application_header,
        json={"account_reference": "acct_pytest_user"},
    )
    assert verified_account.status_code == 400
    assert verified_account.json()["status"] == "VERIFICATION_NOT_AVAILABLE"


def test_phone_verification_can_be_resent_after_cooldown(api, enable_services, application_header, password):
    client, db_sessions, _ = api
    enable_services("SIGNUP", "PHONE_VERIFICATION")
    signup = client.post(
        "/api/v1/auth/signup",
        headers=application_header,
        json={
            "email": "resend-phone@example.com",
            "phone": "+14155550123",
            "password": password,
        },
    )
    assert signup.status_code == 201, signup.text
    account_reference = signup.json()["data"]["account_reference"]
    original = signup.json()["data"]["phone_verification"]
    with db_sessions() as db:
        challenge = db.get(PhoneVerificationChallenge, ("app_pytest", original["verification_reference"]))
        challenge.created_at = utc_now() - timedelta(minutes=2)
        challenge.expires_at = utc_now() - timedelta(minutes=1)
        db.commit()

    resent = client.post(
        "/api/v1/auth/verify/phone/resend",
        headers=application_header,
        json={"account_reference": account_reference},
    )
    assert resent.status_code == 200, resent.text
    new_challenge = resent.json()["data"]
    assert new_challenge["channel"] == "PHONE"
    assert new_challenge["verification_reference"] != original["verification_reference"]
    verified = client.post(
        "/api/v1/auth/verify/phone",
        headers=application_header,
        json={
            "verification_reference": new_challenge["verification_reference"],
            "code": new_challenge["code"],
        },
    )
    assert verified.status_code == 200, verified.text
    with db_sessions() as db:
        account = db.get(AuthenticationAccount, ("app_pytest", account_reference))
        assert account.phone_verified is True
        assert account.status == "ACTIVE"


def test_password_reset_revokes_all_existing_refresh_sessions(
    api, enable_services, create_test_account, application_header, password, login_user, issue_user_tokens
):
    client, db_sessions, _ = api
    enable_services("LOGIN", "TOKEN", "PASSWORD_RECOVERY")
    create_test_account(db_sessions)
    session_tokens = []
    for _ in range(2):
        login = login_user(client)
        session_tokens.append(issue_user_tokens(client, login["data"]["authentication_reference"]))

    recovery = client.post(
        "/api/v1/auth/password/recovery",
        headers=application_header,
        json={"identifier": "user@example.com"},
    )
    assert recovery.status_code == 200, recovery.text
    details = recovery.json()["data"]
    reset = client.post(
        "/api/v1/auth/password/reset",
        headers=application_header,
        json={
            "recovery_reference": details["recovery_reference"],
            "verification_code": details["verification_code"],
            "new_password": "a brand new password",
        },
    )
    assert reset.status_code == 200, reset.text

    for tokens in session_tokens:
        refreshed = client.post(
            "/api/v1/tokens/refresh",
            headers=application_header,
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert refreshed.status_code == 401
        assert refreshed.json()["status"] == "INVALID_REFRESH_TOKEN"

    with db_sessions() as db:
        sessions = db.query(UserSession).filter_by(
            application_id="app_pytest", account_reference="acct_pytest_user"
        ).all()
        assert len(sessions) == 2
        assert all(session.revoked_at is not None for session in sessions)


def test_enabling_services_adds_default_scopes_to_existing_clients_without_manage_scope(api):
    client, _, _ = api
    registered = client.post(
        "/api/v1/applications",
        headers=PLATFORM_HEADER,
        json={
            "name": "Scope Sync Test App",
            "application_type": "EXTERNAL",
            "client_type": "CONFIDENTIAL",
            "configuration": {"enabled_services": ["SIGNUP"]},
        },
    )
    assert registered.status_code == 201, registered.text
    application_id = registered.json()["data"]["application_id"]
    assert registered.json()["data"]["client"]["scopes"] == ["authentication:signup"]

    configured = client.put(
        f"/api/v1/applications/{application_id}/services",
        headers=PLATFORM_HEADER,
        json={"services": [
            {"service_code": "SIGNUP", "enabled": True},
            {"service_code": "OTP", "enabled": True},
            {"service_code": "AUDIT", "enabled": True},
            {"service_code": "AUTHORIZATION", "enabled": True},
        ]},
    )
    assert configured.status_code == 200, configured.text
    details = client.get(
        f"/api/v1/applications/{application_id}", headers=PLATFORM_HEADER
    ).json()["data"]
    scopes = set(details["clients"][0]["scopes"])
    assert scopes == {
        "authentication:signup", "authentication:otp", "audit:read", "authorization:check"
    }
    assert "authorization:manage" not in scopes


def test_per_ip_rate_limit_returns_retry_after(api, enable_services, application_header, monkeypatch):
    client, _, settings = api
    enable_services("LOGIN")
    monkeypatch.setattr(settings, "rate_limit_ip_per_minute", 3)

    responses = [_login(client, application_header, identifier=f"ghost-{n}@example.com") for n in range(4)]
    assert [response.status_code for response in responses] == [401, 401, 401, 429]
    assert responses[-1].json()["status"] == "RATE_LIMITED"
    assert int(responses[-1].headers["Retry-After"]) >= 1


def test_identifier_rate_limit_applies_to_password_recovery(
    api, enable_services, application_header, monkeypatch
):
    client, _, settings = api
    enable_services("PASSWORD_RECOVERY")
    monkeypatch.setattr(settings, "rate_limit_identifier_attempts", 2)
    request = {"identifier": "unknown@example.com"}
    statuses = [
        client.post("/api/v1/auth/password/recovery", headers=application_header, json=request).status_code
        for _ in range(3)
    ]
    assert statuses == [200, 200, 429]


def test_unknown_identifier_follows_same_lockout_response_sequence(api, enable_services, application_header):
    client, _, _ = api
    enable_services("LOGIN")
    statuses = [
        _login(client, application_header, identifier="unknown@example.com").json()["status"]
        for _ in range(4)
    ]
    assert statuses == [
        "AUTHENTICATION_FAILED",
        "AUTHENTICATION_FAILED",
        "RECOVERY_REQUIRED",
        "RECOVERY_REQUIRED",
    ]


@pytest.mark.parametrize(
    ("app_env", "allow_dev_header"),
    [("development", False), ("production", True), ("production", False)],
)
def test_dev_identity_header_requires_development_and_explicit_flag(
    api, enable_services, application_header, monkeypatch, app_env, allow_dev_header
):
    client, _, settings = api
    enable_services("AUDIT")
    monkeypatch.setattr(settings, "app_env", app_env)
    monkeypatch.setattr(settings, "allow_dev_identity_header", allow_dev_header)
    response = client.get("/api/v1/audit/events", headers=application_header)
    if app_env == "development" and allow_dev_header:
        assert response.status_code == 200, response.text
    else:
        assert response.status_code == 401
        assert response.json()["status"] == "UNAUTHENTICATED"


def test_audit_events_capture_masked_login_outcomes_and_paginate(
    api, enable_services, create_test_account, application_header, password
):
    client, db_sessions, _ = api
    enable_services("LOGIN", "TOKEN", "AUDIT")
    create_test_account(db_sessions)
    failed = _login(client, application_header, password="wrong password")
    assert failed.status_code == 401
    success = _login(client, application_header, password=password)
    assert success.status_code == 200

    everything = client.get("/api/v1/audit/events", headers=application_header)
    assert everything.status_code == 200, everything.text
    events = everything.json()["data"]["events"]
    assert [(event["event_type"], event["outcome"]) for event in events] == [
        ("AUTH_LOGIN", "SUCCESS"), ("AUTH_LOGIN", "FAILURE")
    ]
    assert events[1]["error_code"] == "AUTHENTICATION_FAILED"
    assert events[0]["account_reference"] == "acct_pytest_user"
    assert events[0]["details"]["identifier"] == "u***@example.com"
    assert password not in everything.text
    assert "wrong password" not in everything.text

    failures = client.get("/api/v1/audit/events?outcome=FAILURE", headers=application_header)
    assert [event["outcome"] for event in failures.json()["data"]["events"]] == ["FAILURE"]
    first_page = client.get("/api/v1/audit/events?limit=1", headers=application_header).json()["data"]
    assert len(first_page["events"]) == 1
    assert first_page["next_cursor"]
    second_page = client.get(
        f"/api/v1/audit/events?limit=1&cursor={first_page['next_cursor']}",
        headers=application_header,
    ).json()["data"]
    assert [event["outcome"] for event in second_page["events"]] == ["FAILURE"]
    assert second_page["next_cursor"] is None


def test_audit_is_not_recorded_or_readable_when_service_is_disabled(
    api, enable_services, create_test_account
):
    client, db_sessions, _ = api
    enable_services("LOGIN")
    create_test_account(db_sessions)
    assert _login(client, {"X-Dev-Application-Id": "app_pytest"}).status_code == 401

    with db_sessions() as db:
        assert db.query(AuditEvent).count() == 0
    denied = client.get("/api/v1/audit/events", headers={"X-Dev-Application-Id": "app_pytest"})
    assert denied.status_code == 403
    assert denied.json()["status"] == "SERVICE_NOT_ENABLED"
