import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from alzando_authorization.config import settings
from alzando_authorization.models import (
    Application,
    AuthenticationAccount,
    AuthenticationGrant,
    UserSession,
    utc_now,
)
from alzando_authorization.service import ServiceError
from alzando_authorization.tokens import AccessTokenService


def issue_user_tokens(
    db: Session,
    application_id: str,
    authentication_reference: str,
    token_service: AccessTokenService,
) -> dict:
    grant = db.scalar(select(AuthenticationGrant).where(
        AuthenticationGrant.application_id == application_id,
        AuthenticationGrant.authentication_reference == authentication_reference,
    ).with_for_update())
    now = utc_now()
    if grant is None or grant.used_at is not None or grant.expires_at <= now:
        raise ServiceError("INVALID_AUTHENTICATION_GRANT", "Authentication grant is invalid or expired.", 400)
    if grant.mfa_required and not grant.mfa_verified:
        raise ServiceError("MFA_REQUIRED", "Complete the MFA challenge before requesting tokens.", 401)

    account = db.get(AuthenticationAccount, (application_id, grant.account_reference))
    if account is None or account.status != "ACTIVE":
        db.rollback()
        raise ServiceError("ACCOUNT_UNAVAILABLE", "The account is not active.", 401)
    application = db.get(Application, application_id)
    if application is None or application.status != "ACTIVE":
        db.rollback()
        raise ServiceError("APPLICATION_INACTIVE", "The application is not active.", 403)

    grant.used_at = now
    payload = _create_session(
        db, application_id, account.account_reference, token_service, now, grant.mfa_verified
    )
    db.commit()
    return payload


def refresh_user_tokens(
    db: Session,
    application_id: str,
    refresh_token: str,
    token_service: AccessTokenService,
) -> dict:
    now = utc_now()
    old_session = db.scalar(select(UserSession).where(
        UserSession.application_id == application_id,
        UserSession.refresh_token_hash == _digest(refresh_token),
    ).with_for_update())
    if old_session is None:
        raise _invalid_refresh_token()
    if old_session.revoked_at is not None:
        if old_session.rotated_to_session_id is not None:
            db.execute(update(UserSession).where(
                UserSession.application_id == application_id,
                UserSession.account_reference == old_session.account_reference,
                UserSession.revoked_at.is_(None),
            ).values(revoked_at=now))
            db.commit()
        raise _invalid_refresh_token()
    if old_session.refresh_expires_at <= now:
        old_session.revoked_at = now
        db.commit()
        raise _invalid_refresh_token()

    account = db.get(AuthenticationAccount, (application_id, old_session.account_reference))
    application = db.get(Application, application_id)
    if account is None or account.status != "ACTIVE" or application is None or application.status != "ACTIVE":
        old_session.revoked_at = now
        db.commit()
        raise _invalid_refresh_token()

    old_session.revoked_at = now
    payload = _create_session(
        db, application_id, account.account_reference, token_service, now, old_session.mfa_authenticated
    )
    old_session.rotated_to_session_id = payload["session_id"]
    db.commit()
    return payload


def revoke_user_token(db: Session, application_id: str, refresh_token: str) -> None:
    session = db.scalar(select(UserSession).where(
        UserSession.application_id == application_id,
        UserSession.refresh_token_hash == _digest(refresh_token),
    ).with_for_update())
    if session is not None and session.revoked_at is None:
        session.revoked_at = utc_now()
        db.commit()
    elif session is not None:
        db.rollback()
    # Revocation is idempotent and does not reveal whether a supplied token existed.


def _create_session(
    db: Session,
    application_id: str,
    account_reference: str,
    token_service: AccessTokenService,
    now,
    mfa_authenticated: bool,
) -> dict:
    session_id = f"ses_{secrets.token_urlsafe(18)}"
    refresh_token = f"rft_{secrets.token_urlsafe(48)}"
    refresh_expires_at = now + timedelta(seconds=settings.refresh_token_ttl_seconds)
    db.add(UserSession(
        application_id=application_id,
        session_id=session_id,
        account_reference=account_reference,
        refresh_token_hash=_digest(refresh_token),
        mfa_authenticated=mfa_authenticated,
        refresh_expires_at=refresh_expires_at,
        revoked_at=None,
        rotated_to_session_id=None,
    ))
    return {
        "access_token": token_service.issue_user(
            account_reference, application_id, session_id, mfa_authenticated
        ),
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_seconds,
        "refresh_token": refresh_token,
        "refresh_expires_in": settings.refresh_token_ttl_seconds,
        "account_reference": account_reference,
        "session_id": session_id,
    }


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _invalid_refresh_token() -> ServiceError:
    return ServiceError("INVALID_REFRESH_TOKEN", "Refresh token is invalid, expired, or revoked.", 401)
