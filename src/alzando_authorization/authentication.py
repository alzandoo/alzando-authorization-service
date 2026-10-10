import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alzando_authorization.config import settings
from alzando_authorization.email_verification import create_email_verification_challenge
from alzando_authorization.models import (
    ApplicationService,
    AuthenticationAccount,
    AuthenticationGrant,
    utc_now,
)
from alzando_authorization.rate_limit import RateLimiter
from alzando_authorization.schemas import LoginRequest, SignupRequest
from alzando_authorization.service import ServiceError

password_hasher = PasswordHasher()
_DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(32))
MAX_FAILED_PASSWORD_ATTEMPTS = 3


def signup(db: Session, application_id: str, request: SignupRequest) -> dict:
    email_verification_enabled = bool(db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "EMAIL_VERIFICATION",
    )))
    phone_verification_enabled = bool(db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "PHONE_VERIFICATION",
    )))
    if phone_verification_enabled and not request.phone:
        raise ServiceError("PHONE_REQUIRED", "A phone number is required when Phone Verification is enabled.", 422)
    account = AuthenticationAccount(
        application_id=application_id,
        account_reference=f"acct_{secrets.token_urlsafe(18)}",
        email=request.email,
        phone=request.phone,
        display_name=request.display_name,
        password_hash=password_hasher.hash(request.password),
        status="PENDING_VERIFICATION" if email_verification_enabled or phone_verification_enabled else "ACTIVE",
        email_verified=not email_verification_enabled,
        phone_verified=not phone_verification_enabled,
        failed_login_attempts=0,
    )
    verification = None
    phone_verification = None
    db.add(account)
    try:
        db.flush()
        if email_verification_enabled:
            verification = create_email_verification_challenge(db, application_id, account)
        if phone_verification_enabled:
            from alzando_authorization.phone_verification import create_phone_verification_challenge

            phone_verification = create_phone_verification_challenge(db, application_id, account)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ServiceError(
            "ACCOUNT_ALREADY_EXISTS", "An account already exists for the supplied email or phone.", 409
        ) from None
    verification_response = None
    deliveries = []
    if verification:
        verification_response = {
            "channel": "EMAIL",
            "verification_reference": verification["verification_reference"],
        }
        if "code" in verification:
            verification_response.update({
                "code": verification["code"],
                "expires_in_seconds": verification["expires_in_seconds"],
                "development_only": True,
            })
        if verification.get("delivery"):
            deliveries.append(verification["delivery"])
    phone_verification_response = None
    if phone_verification:
        phone_verification_response = {"channel": "PHONE", **phone_verification}
    result = {
        "status": "VERIFICATION_REQUIRED" if email_verification_enabled or phone_verification_enabled else "ACCOUNT_CREATED",
        "data": {
            "account_reference": account.account_reference,
            "verification": verification_response,
            "phone_verification": phone_verification_response,
        },
    }
    if deliveries:
        result["deliveries"] = deliveries
    return result


def login(
    db: Session, application_id: str, request: LoginRequest, failure_tracker: RateLimiter | None = None
) -> dict:
    identifier = request.identifier.strip().lower()
    account = db.scalar(select(AuthenticationAccount).where(
        AuthenticationAccount.application_id == application_id,
        AuthenticationAccount.email == identifier,
    ).with_for_update())

    if account is None:
        _verify_password(_DUMMY_PASSWORD_HASH, request.password)
        # Mirror the lockout progression of real accounts so the response sequence for an unknown
        # identifier is indistinguishable from a known one (no account enumeration).
        if failure_tracker is not None:
            attempts = failure_tracker.hit(
                f"unknown-login:{application_id}:{identifier}",
                settings.rate_limit_identifier_window_seconds,
            )
            if attempts == MAX_FAILED_PASSWORD_ATTEMPTS:
                raise ServiceError("RECOVERY_REQUIRED", "Password recovery is required.", 401)
            if attempts > MAX_FAILED_PASSWORD_ATTEMPTS:
                raise ServiceError(
                    "RECOVERY_REQUIRED", "Password recovery is required before another login attempt.", 401
                )
        raise ServiceError("AUTHENTICATION_FAILED", "Authentication failed.", 401)

    if account.recovery_required:
        # Spend the same hashing time as any other failed login so timing does not reveal the lock.
        _verify_password(_DUMMY_PASSWORD_HASH, request.password)
        raise ServiceError("RECOVERY_REQUIRED", "Password recovery is required before another login attempt.", 401)

    if not _verify_password(account.password_hash, request.password):
        account.failed_login_attempts += 1
        if account.failed_login_attempts >= MAX_FAILED_PASSWORD_ATTEMPTS:
            account.recovery_required = True
            db.commit()
            raise ServiceError("RECOVERY_REQUIRED", "Password recovery is required.", 401)
        db.commit()
        raise ServiceError("AUTHENTICATION_FAILED", "Authentication failed.", 401)

    account.failed_login_attempts = 0
    db.commit()

    if account.status == "PENDING_VERIFICATION":
        return {
            "status": "VERIFICATION_REQUIRED",
            "data": {"account_reference": account.account_reference},
        }
    if account.status != "ACTIVE":
        raise ServiceError("ACCOUNT_UNAVAILABLE", "The account is not active.", 401)

    token_service_enabled = bool(db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "TOKEN",
    )))
    if not token_service_enabled:
        raise ServiceError("SERVICE_NOT_ENABLED", "Token Services is not enabled for this application.", 403)

    mfa_required = bool(db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "MFA",
    )))
    if mfa_required and not db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "OTP",
    )):
        raise ServiceError("MFA_UNAVAILABLE", "MFA requires the OTP service to be enabled.", 503)

    authentication_reference = f"ath_{secrets.token_urlsafe(18)}"
    db.add(AuthenticationGrant(
        application_id=application_id,
        authentication_reference=authentication_reference,
        account_reference=account.account_reference,
        mfa_required=mfa_required,
        mfa_verified=False,
        expires_at=utc_now() + timedelta(seconds=settings.authentication_grant_ttl_seconds),
    ))
    db.commit()
    if mfa_required:
        return {
            "status": "MFA_REQUIRED",
            "data": {
                "account_reference": account.account_reference,
                "authentication_reference": authentication_reference,
                "next_step": "COMPLETE_MFA_CHALLENGE",
                "expires_in_seconds": settings.authentication_grant_ttl_seconds,
            },
        }
    return {
        "status": "AUTHENTICATED",
        "data": {
            "account_reference": account.account_reference,
            "authentication_reference": authentication_reference,
            "authentication": None,
            "next_step": "REQUEST_APPLICATION_USER_TOKEN",
            "expires_in_seconds": settings.authentication_grant_ttl_seconds,
        },
    }


def _verify_password(password_hash: str, candidate: str) -> bool:
    try:
        return password_hasher.verify(password_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
