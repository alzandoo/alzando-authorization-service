import hmac
import secrets
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from alzando_authorization.challenge_security import challenge_secret, code_digest
from alzando_authorization.config import settings
from alzando_authorization.email_delivery import email_delivery_configured
from alzando_authorization.models import AuthenticationAccount, EmailVerificationChallenge, utc_now
from alzando_authorization.service import ServiceError
from alzando_authorization.verification_status import activate_when_required_channels_are_verified

MAX_VERIFICATION_CODE_ATTEMPTS = 5


def create_email_verification_challenge(
    db: Session, application_id: str, account: AuthenticationAccount
) -> dict:
    secret = challenge_secret()
    if settings.app_env.lower() != "development" and not email_delivery_configured():
        raise ServiceError("SERVICE_UNAVAILABLE", "Email verification delivery is not configured.", 503)

    now = utc_now()
    code = f"{secrets.randbelow(1_000_000):06d}"
    verification_reference = f"ver_{secrets.token_urlsafe(18)}"
    challenge = EmailVerificationChallenge(
        application_id=application_id,
        verification_reference=verification_reference,
        account_reference=account.account_reference,
        code_digest=code_digest(secret, application_id, verification_reference, code),
        expires_at=now + timedelta(seconds=settings.email_verification_ttl_seconds),
        used_at=None,
        failed_attempts=0,
    )
    db.add(challenge)

    result = {"verification_reference": verification_reference}
    is_development = settings.app_env.lower() == "development"
    if is_development:
        result.update({
            "code": code,
            "expires_in_seconds": settings.email_verification_ttl_seconds,
            "development_only": True,
        })
    # Development can still exercise real provider delivery when SMTP is configured.
    # Keep returning the code only in development so local flows work without a mailbox.
    if email_delivery_configured():
        result["delivery"] = {
            "recipient": account.email,
            "subject": "Verify your email address",
            "body": (
                "Use this code to verify your email address.\n\n"
                f"Verification code: {code}\n"
                f"This code expires in {settings.email_verification_ttl_seconds} seconds.\n"
                "If you did not create this account, you can ignore this email."
            ),
        }
    return result


def verify_email(db: Session, application_id: str, verification_reference: str, code: str) -> dict:
    secret = challenge_secret()
    challenge = db.scalar(select(EmailVerificationChallenge).where(
        EmailVerificationChallenge.application_id == application_id,
        EmailVerificationChallenge.verification_reference == verification_reference,
    ).with_for_update())
    now = utc_now()
    if (
        challenge is None
        or challenge.used_at is not None
        or challenge.expires_at <= now
        or challenge.failed_attempts >= MAX_VERIFICATION_CODE_ATTEMPTS
    ):
        raise ServiceError("INVALID_VERIFICATION_CHALLENGE", "Verification challenge is invalid or expired.", 400)

    candidate_digest = code_digest(secret, application_id, verification_reference, code)
    if not hmac.compare_digest(challenge.code_digest, candidate_digest):
        challenge.failed_attempts += 1
        if challenge.failed_attempts >= MAX_VERIFICATION_CODE_ATTEMPTS:
            challenge.used_at = now
        db.commit()
        raise ServiceError("INVALID_VERIFICATION_CHALLENGE", "Verification challenge is invalid or expired.", 400)

    account = db.get(AuthenticationAccount, (application_id, challenge.account_reference))
    if account is None:
        db.rollback()
        raise ServiceError("INVALID_VERIFICATION_CHALLENGE", "Verification challenge is invalid or expired.", 400)

    account.email_verified = True
    challenge.used_at = now
    db.execute(update(EmailVerificationChallenge).where(
        EmailVerificationChallenge.application_id == application_id,
        EmailVerificationChallenge.account_reference == account.account_reference,
        EmailVerificationChallenge.verification_reference != challenge.verification_reference,
        EmailVerificationChallenge.used_at.is_(None),
    ).values(used_at=now))
    activate_when_required_channels_are_verified(db, application_id, account)
    db.commit()
    return {"channel": "EMAIL", "verified": True}


def resend_email_verification(db: Session, application_id: str, account_reference: str) -> dict:
    """Issue a fresh email verification code for an account that is still pending."""
    now = utc_now()
    account = db.scalar(select(AuthenticationAccount).where(
        AuthenticationAccount.application_id == application_id,
        AuthenticationAccount.account_reference == account_reference,
    ).with_for_update())
    if account is None or account.status != "PENDING_VERIFICATION" or account.email_verified:
        raise ServiceError(
            "VERIFICATION_NOT_AVAILABLE", "Email verification is not available for this account.", 400
        )

    recent = db.scalar(select(EmailVerificationChallenge).where(
        EmailVerificationChallenge.application_id == application_id,
        EmailVerificationChallenge.account_reference == account.account_reference,
    ).order_by(EmailVerificationChallenge.created_at.desc()).limit(1))
    interval = settings.verification_resend_interval_seconds
    if recent and recent.created_at > now - timedelta(seconds=interval):
        wait = max(1, interval - int((now - recent.created_at).total_seconds()))
        db.rollback()
        raise ServiceError(
            "VERIFICATION_RATE_LIMITED", "Wait before requesting another code.", 429,
            headers={"Retry-After": str(wait)},
        )

    db.execute(update(EmailVerificationChallenge).where(
        EmailVerificationChallenge.application_id == application_id,
        EmailVerificationChallenge.account_reference == account.account_reference,
        EmailVerificationChallenge.used_at.is_(None),
    ).values(used_at=now))
    try:
        result = create_email_verification_challenge(db, application_id, account)
    except ServiceError:
        db.rollback()
        raise
    db.commit()
    return result
