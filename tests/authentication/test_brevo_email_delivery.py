"""Unit tests for Brevo HTTPS email delivery."""

import io
import json
from urllib.error import HTTPError, URLError

from alzando_authorization import email_delivery


def test_email_delivery_configured_when_brevo_is_configured(
    monkeypatch,
):
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_api_key",
        "xkeysib-test-api-key",
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_email",
        "sender@example.com",
    )

    assert email_delivery.email_delivery_configured() is True


def test_brevo_email_builds_correct_request(
    monkeypatch,
):
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_api_key",
        "xkeysib-test-api-key",
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_email",
        "sender@example.com",
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_name",
        "Alzando",
    )

    captured = {}

    class FakeResponse:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        email_delivery,
        "urlopen",
        fake_urlopen,
    )

    email_delivery.send_configured_email(
        recipient="recipient@example.com",
        subject="Verify your email",
        body="Your verification code is 123456",
    )

    request = captured["request"]

    assert request.full_url == "https://api.brevo.com/v3/smtp/email"
    assert captured["timeout"] == 10

    assert request.headers["Api-key"] == "xkeysib-test-api-key"
    assert request.headers["Content-type"] == "application/json"

    payload = json.loads(request.data.decode("utf-8"))

    assert payload == {
        "sender": {
            "name": "Alzando",
            "email": "sender@example.com",
        },
        "to": [
            {
                "email": "recipient@example.com",
            }
        ],
        "subject": "Verify your email",
        "textContent": "Your verification code is 123456",
    }


def test_brevo_http_error_does_not_expose_secret_in_logs(
    monkeypatch,
    caplog,
):
    api_key = "xkeysib-test-secret"

    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_api_key",
        api_key,
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_email",
        "sender@example.com",
    )

    error = HTTPError(
        url=email_delivery.BREVO_API_URL,
        code=400,
        msg="Bad Request",
        hdrs=None,
        fp=io.BytesIO(b'{"message":"invalid request"}'),
    )

    def fake_urlopen(request, timeout):
        raise error

    monkeypatch.setattr(
        email_delivery,
        "urlopen",
        fake_urlopen,
    )

    email_delivery.send_configured_email(
        recipient="recipient@example.com",
        subject="Test",
        body="Sensitive verification code: 123456",
    )

    assert api_key not in caplog.text
    assert "Sensitive verification code: 123456" not in caplog.text
    assert "recipient@example.com" not in caplog.text


def test_brevo_network_error_does_not_expose_email_contents(
    monkeypatch,
    caplog,
):
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_api_key",
        "xkeysib-test-api-key",
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_email",
        "sender@example.com",
    )

    def fake_urlopen(request, timeout):
        raise URLError("network unavailable")

    monkeypatch.setattr(
        email_delivery,
        "urlopen",
        fake_urlopen,
    )

    email_delivery.send_configured_email(
        recipient="recipient@example.com",
        subject="Private subject",
        body="Private verification code: 654321",
    )

    assert "recipient@example.com" not in caplog.text
    assert "Private subject" not in caplog.text
    assert "Private verification code: 654321" not in caplog.text


def test_smtp_is_used_when_brevo_is_not_configured(
    monkeypatch,
):
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_api_key",
        None,
    )
    monkeypatch.setattr(
        email_delivery.settings,
        "brevo_from_email",
        None,
    )

    sent = {}

    def fake_smtp(recipient, subject, body):
        sent["recipient"] = recipient
        sent["subject"] = subject
        sent["body"] = body

    monkeypatch.setattr(
        email_delivery,
        "_send_via_smtp",
        fake_smtp,
    )

    email_delivery.send_configured_email(
        recipient="recipient@example.com",
        subject="SMTP fallback",
        body="Fallback message",
    )

    assert sent == {
        "recipient": "recipient@example.com",
        "subject": "SMTP fallback",
        "body": "Fallback message",
    }