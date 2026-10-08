import hmac
import secrets
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from alzando_authorization.challenge_security import challenge_secret, code_digest
from alzando_authorization.config import settings
from alzando_authorization.email_delivery import email_delivery_configured
from alzando_authorization.models import (
    ApplicationService,
    AuthenticationAccount,
    OtpChallenge,
    utc_now,
)
from alzando_authorization.schemas import OtpRequest
from alzando_authorization.service import ServiceError

MAX_OTP_ATTEMPTS = 5


def request_otp(
    db: Session, application_id: str, request: OtpRequest,
    authentication_reference: str | None = None,
) -> dict:
    if request.purpose == "MFA" and authentication_reference is None:
        raise ServiceError("AUTHENTICATION_GRANT_REQUIRED", "Complete password login before starting an MFA challenge.", 400)
    _require_purpose_enabled(db, application_id, request)
    if request.channel == "SMS" and settings.app_env.lower() != "development":
        raise ServiceError("SERVICE_UNAVAILABLE", "An SMS delivery provider is not configured.", 503)
    if request.channel == "EMAIL" and settings.app_env.lower() != "development" and not email_delivery_configured():
        raise ServiceError("SERVICE_UNAVAILABLE", "Email delivery is not configured.", 503)

    now = utc_now()
    secret = challenge_secret()
    account = db.get(AuthenticationAccount, (application_id, request.account_reference))
    if account is not None:
        if request.channel == "SMS" and not account.phone:
            raise ServiceError("OTP_CHANNEL_UNAVAILABLE", "The account has no phone number for this channel.", 400)
        if request.channel == "EMAIL" and not account.email:
            raise ServiceError("OTP_CHANNEL_UNAVAILABLE", "The account has no email address for this channel.", 400)
        if request.purpose in {"LOGIN", "MFA"}:
            verified = account.email_verified if request.channel == "EMAIL" else account.phone_verified
            if not verified:
                raise ServiceError("OTP_CHANNEL_UNAVAILABLE", "The account channel must be verified first.", 400)

    recent = db.scalar(select(OtpChallenge).where(
        OtpChallenge.application_id == application_id,
        OtpChallenge.subject_reference == request.account_reference,
        OtpChallenge.purpose == request.purpose,
        OtpChallenge.channel == request.channel,
    ).order_by(OtpChallenge.created_at.desc()).limit(1))
    if (
        recent
        and recent.expires_at > now
        and recent.created_at > now - timedelta(seconds=settings.otp_resend_interval_seconds)
    ):
        if recent.used_at is not None:
            raise ServiceError("OTP_RATE_LIMITED", "Wait before requesting another code.", 429)
        recent.authentication_reference = authentication_reference
        db.commit()
        return {
            "status": "OTP_REQUESTED",
            "data": {
                "challenge_reference": recent.challenge_reference,
                "expires_in_seconds": max(0, int((recent.expires_at - now).total_seconds())),
                "retry_after_seconds": max(1, settings.otp_resend_interval_seconds - int((now - recent.created_at).total_seconds())),
            },
        }

    db.execute(update(OtpChallenge).where(
        OtpChallenge.application_id == application_id,
        OtpChallenge.subject_reference == request.account_reference,
        OtpChallenge.purpose == request.purpose,
        OtpChallenge.channel == request.channel,
        OtpChallenge.used_at.is_(None),
    ).values(used_at=now))

    code = f"{secrets.randbelow(1_000_000):06d}"
    reference = f"otp_{secrets.token_urlsafe(18)}"
    challenge = OtpChallenge(
        application_id=application_id,
        challenge_reference=reference,
        subject_reference=request.account_reference,
        account_reference=account.account_reference if account else None,
        authentication_reference=authentication_reference,
        purpose=request.purpose,
        channel=request.channel,
        code_digest=code_digest(secret, application_id, reference, code),
        expires_at=now + timedelta(seconds=settings.otp_ttl_seconds),
        used_at=None,
        failed_attempts=0,
    )
    db.add(challenge)
    db.commit()

    data = {
        "challenge_reference": reference,
        "expires_in_seconds": settings.otp_ttl_seconds,
        "channel": request.channel,
        "purpose": request.purpose,
    }
    result = {"status": "OTP_REQUESTED", "data": data}
    if settings.app_env.lower() == "development":
        data.update({"otp": code, "development_only": True})
    if account is not None and request.channel == "EMAIL" and email_delivery_configured():
        result["delivery"] = {
            "recipient": account.email,
            "subject": "Your Alzando verification code",
            "body": (
                f"Your one-time password is {code}.\n\n"
                f"It expires in {settings.otp_ttl_seconds} seconds. "
                "If you did not request this code, you can ignore this email."
            ),
        }
    return result


def verify_otp(
    db: Session, application_id: str, reference: str, otp: str,
    expected_purpose: str | None = None,
) -> dict:
    secret = challenge_secret()
    challenge = db.scalar(select(OtpChallenge).where(
        OtpChallenge.application_id == application_id,
        OtpChallenge.challenge_reference == reference,
    ).with_for_update())
    now = utc_now()
    invalid = (
        challenge is None
        or challenge.used_at is not None
        or challenge.expires_at <= now
        or challenge.failed_attempts >= MAX_OTP_ATTEMPTS
        or (expected_purpose is not None and challenge.purpose != expected_purpose)
        or (challenge is not None and challenge.purpose == "MFA" and expected_purpose != "MFA")
    )
    if invalid:
        raise _invalid_challenge()

    supplied = code_digest(secret, application_id, reference, otp)
    if not hmac.compare_digest(challenge.code_digest, supplied):
        challenge.failed_attempts += 1
        if challenge.failed_attempts >= MAX_OTP_ATTEMPTS:
            challenge.used_at = now
        db.commit()
        raise _invalid_challenge()

    if challenge.account_reference is None:
        challenge.used_at = now
        db.commit()
        raise _invalid_challenge()

    challenge.used_at = now
    db.execute(update(OtpChallenge).where(
        OtpChallenge.application_id == application_id,
        OtpChallenge.subject_reference == challenge.subject_reference,
        OtpChallenge.purpose == challenge.purpose,
        OtpChallenge.channel == challenge.channel,
        OtpChallenge.challenge_reference != challenge.challenge_reference,
        OtpChallenge.used_at.is_(None),
    ).values(used_at=now))
    db.commit()
    return {
        "challenge_reference": reference,
        "account_reference": challenge.account_reference,
        "purpose": challenge.purpose,
        "channel": challenge.channel,
        "authentication_reference": challenge.authentication_reference,
        "verified": True,
    }


def _require_purpose_enabled(db: Session, application_id: str, request: OtpRequest) -> None:
    service_by_purpose = {
        "LOGIN": "LOGIN",
        "MFA": "MFA",
        "RECOVERY": "PASSWORD_RECOVERY",
        "VERIFICATION": "EMAIL_VERIFICATION" if request.channel == "EMAIL" else "PHONE_VERIFICATION",
    }
    required_services = {"OTP", service_by_purpose[request.purpose]}
    enabled = set(db.scalars(select(ApplicationService.service_code).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code.in_(required_services),
        ApplicationService.enabled.is_(True),
    )).all())
    missing = required_services - enabled
    if missing:
        service = sorted(missing)[0]
        raise ServiceError("SERVICE_NOT_ENABLED", f"{service.title()} is not enabled for this application.", 403)


def _invalid_challenge() -> ServiceError:
    return ServiceError("INVALID_OTP_CHALLENGE", "OTP challenge is invalid or expired.", 400)
