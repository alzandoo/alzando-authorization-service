import logging
import smtplib
import ssl
from email.message import EmailMessage

from alzando_authorization.config import settings

logger = logging.getLogger(__name__)


def email_delivery_configured() -> bool:
    credentials_are_complete = bool(settings.smtp_username) == bool(settings.smtp_password)
    return bool(settings.smtp_host and settings.smtp_from_email and credentials_are_complete)


def send_configured_email(recipient: str, subject: str, body: str) -> None:
    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = settings.smtp_from_email
        message["To"] = recipient
        message.set_content(body)
        if settings.smtp_starttls:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
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
    except Exception:
        # Avoid logging the destination address or message contents, which can contain codes.
        logger.error("Configured email delivery failed.")


def _login_and_send(client: smtplib.SMTP, message: EmailMessage) -> None:
    if settings.smtp_username and settings.smtp_password:
        client.login(settings.smtp_username, settings.smtp_password)
    client.send_message(message)
