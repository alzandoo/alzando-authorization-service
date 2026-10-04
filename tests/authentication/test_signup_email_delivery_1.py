"""Test 1: Deliver the email verification message after signup.

Enable Signup and Email Verification, submit a valid registration, and stub
the challenge creator to return a delivery payload. The API should return
VERIFICATION_REQUIRED and enqueue that payload for the email sender.
"""

from alzando_authorization import authentication, main as main_module

def test_signup_queues_email_verification_delivery(
    api, enable_services, monkeypatch, application_header, password
):
    """A signup that needs email verification schedules its verification email."""
    client, _, _ = api
    enable_services("SIGNUP", "EMAIL_VERIFICATION")
    delivery = {"recipient": "new@example.com", "subject": "Verify", "body": "Code"}
    sent = []
    monkeypatch.setattr(
        authentication,
        "create_email_verification_challenge",
        lambda *_args: {"verification_reference": "ver_pytest", "delivery": delivery},
    )
    monkeypatch.setattr(main_module, "send_configured_email", lambda **kwargs: sent.append(kwargs))

    response = client.post(
        "/api/v1/auth/signup",
        headers=application_header,
        json={"email": "new@example.com", "password": password},
    )

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "VERIFICATION_REQUIRED"
    assert sent == [delivery]
