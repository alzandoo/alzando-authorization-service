import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from alzando_authorization.config import settings

logger = logging.getLogger(__name__)

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def email_delivery_configured() -> bool:
    if settings.brevo_api_key and settings.brevo_from_email:
        return True

    credentials_are_complete = bool(settings.smtp_username) == bool(settings.smtp_password)
    return bool(
        settings.smtp_host
        and settings.smtp_from_email
        and credentials_are_complete
    )


def send_configured_email(recipient: str, subject: str, body: str) -> None:
    try:
        if settings.brevo_api_key and settings.brevo_from_email:
            _send_via_brevo(recipient, subject, body)
        else:
            _send_via_smtp(recipient, subject, body)
    except Exception as exc:   # noqa: BLE001
        # Never log the recipient, message contents, or API credentials.
        logger.error("Configured email delivery failed (%s).", type(exc).__name__)


def _send_via_brevo(recipient: str, subject: str, body: str) -> None:
    payload = {
        "sender": {
            "name": settings.brevo_from_name,
            "email": settings.brevo_from_email,
        },
        "to": [
            {
                "email": recipient,
            }
        ],
        "subject": subject,
        "textContent": body,
    }

    request = Request(
        BREVO_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "api-key": settings.brevo_api_key,
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"Brevo email delivery returned HTTP {response.status}"
                )
    except HTTPError as exc:
        logger.error("Brevo email delivery failed with HTTP %s.", exc.code)
        raise
    except URLError:
        logger.error("Brevo email delivery failed due to a network error.")
        raise


def _send_via_smtp(recipient: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(body)

    if settings.smtp_starttls:
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10,
        ) as client:
            client.starttls(context=ssl.create_default_context())
            _login_and_send(client, message)
    else:
        with smtplib.SMTP_SSL(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10,
            context=ssl.create_default_context(),
        ) as client:
            _login_and_send(client, message)


def _login_and_send(client: smtplib.SMTP, message: EmailMessage) -> None:
    if settings.smtp_username and settings.smtp_password:
        client.login(settings.smtp_username, settings.smtp_password)

    client.send_message(message)