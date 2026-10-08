import hmac
import secrets
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from alzando_authorization.authentication import password_hasher
from alzando_authorization.challenge_security import challenge_secret, code_digest
from alzando_authorization.config import settings
from alzando_authorization.models import (
    AuthenticationAccount,
    PasswordRecoveryChallenge,
    UserSession,
    utc_now,
)
from alzando_authorization.schemas import PasswordResetRequest
from alzando_authorization.service import ServiceError
from alzando_authorization.email_delivery import email_delivery_configured
MAX_RECOVERY_CODE_ATTEMPTS = 5


def request_password_recovery(db: Session, application_id: str, identifier: str) -> dict:
    secret = challenge_secret()
    if settings.app_env.lower() != "development" and not email_delivery_configured():
        raise ServiceError("SERVICE_UNAVAILABLE", "Password recovery delivery is not configured.", 503)

    now = utc_now()
    db.execute(delete(PasswordRecoveryChallenge).where(
        PasswordRecoveryChallenge.expires_at < now - timedelta(days=1)
    ))
    account = db.scalar(select(AuthenticationAccount).where(
        AuthenticationAccount.application_id == application_id,
        AuthenticationAccount.email == identifier.strip().lower(),
    ).with_for_update())

    response = {
        "status": "RECOVERY_INITIATED",
        "data": {"next_step": "VERIFY_RECOVERY_CHALLENGE"},
    }
    if account is None:
        db.commit()
        return response

    recent_challenge = db.scalar(select(PasswordRecoveryChallenge).where(
        PasswordRecoveryChallenge.application_id == application_id,
        PasswordRecoveryChallenge.account_reference == account.account_reference,
    ).order_by(PasswordRecoveryChallenge.created_at.desc()).limit(1))
    if recent_challenge and recent_challenge.created_at > now - timedelta(
        seconds=settings.password_recovery_resend_interval_seconds
    ):
        db.commit()
        return response

    db.execute(update(PasswordRecoveryChallenge).where(
        PasswordRecoveryChallenge.application_id == application_id,
        PasswordRecoveryChallenge.account_reference == account.account_reference,
        PasswordRecoveryChallenge.used_at.is_(None),
    ).values(used_at=now))

    code = f"{secrets.randbelow(1_000_000):06d}"
    recovery_reference = f"rcv_{secrets.token_urlsafe(18)}"
    challenge = PasswordRecoveryChallenge(
        application_id=application_id,
        recovery_reference=recovery_reference,
        account_reference=account.account_reference,
        code_digest=code_digest(secret, application_id, recovery_reference, code),
        expires_at=now + timedelta(seconds=settings.password_recovery_ttl_seconds),
        used_at=None,
        failed_attempts=0,
    )
    db.add(challenge)
    db.commit()

    is_development = settings.app_env.lower() == "development"
    if is_development:
        response["data"].update({
            "recovery_reference": recovery_reference,
            "verification_code": code,
            "expires_in_seconds": settings.password_recovery_ttl_seconds,
            "development_only": True,
        })
    # Use SMTP in development when configured, while preserving the code-based local fallback.
    if email_delivery_configured():
        response["delivery"] = {
            "recipient": account.email,
            "subject": "Password recovery",
            "body": (
                "Use this code to reset your password.\n\n"
                f"Recovery reference: {recovery_reference}\n"
                f"Verification code: {code}\n"
                f"This code expires in {settings.password_recovery_ttl_seconds} seconds.\n"
                "If you did not request this, you can ignore this email."
            ),
        }
    return response


def complete_password_reset(db: Session, application_id: str, request: PasswordResetRequest) -> dict:
    secret = challenge_secret()
    challenge = db.scalar(select(PasswordRecoveryChallenge).where(
        PasswordRecoveryChallenge.application_id == application_id,
        PasswordRecoveryChallenge.recovery_reference == request.recovery_reference,
    ).with_for_update())
    now = utc_now()
    if (
        challenge is None
        or challenge.used_at is not None
        or challenge.expires_at <= now
        or challenge.failed_attempts >= MAX_RECOVERY_CODE_ATTEMPTS
    ):
        raise ServiceError("INVALID_RECOVERY_CHALLENGE", "Recovery challenge is invalid or expired.", 400)

    candidate_digest = code_digest(
        secret, application_id, request.recovery_reference, request.verification_code
    )
    if not hmac.compare_digest(challenge.code_digest, candidate_digest):
        challenge.failed_attempts += 1
        if challenge.failed_attempts >= MAX_RECOVERY_CODE_ATTEMPTS:
            challenge.used_at = now
        db.commit()
        raise ServiceError("INVALID_RECOVERY_CHALLENGE", "Recovery challenge is invalid or expired.", 400)

    account = db.get(AuthenticationAccount, (application_id, challenge.account_reference))
    if account is None:
        db.rollback()
        raise ServiceError("INVALID_RECOVERY_CHALLENGE", "Recovery challenge is invalid or expired.", 400)

    account.password_hash = password_hasher.hash(request.new_password)
    account.failed_login_attempts = 0
    account.recovery_required = False
    if account.status != "PENDING_VERIFICATION":
        account.status = "ACTIVE"
    challenge.used_at = now
    # A password reset must end every existing session so a stolen refresh token cannot outlive it.
    db.execute(update(UserSession).where(
        UserSession.application_id == application_id,
        UserSession.account_reference == account.account_reference,
        UserSession.revoked_at.is_(None),
    ).values(revoked_at=now))
    db.execute(update(PasswordRecoveryChallenge).where(
        PasswordRecoveryChallenge.application_id == application_id,
        PasswordRecoveryChallenge.account_reference == account.account_reference,
        PasswordRecoveryChallenge.recovery_reference != challenge.recovery_reference,
        PasswordRecoveryChallenge.used_at.is_(None),
    ).values(used_at=now))
    db.commit()
    return {
        "authentication_state": "VERIFICATION_REQUIRED" if account.status == "PENDING_VERIFICATION" else "READY"
    }


