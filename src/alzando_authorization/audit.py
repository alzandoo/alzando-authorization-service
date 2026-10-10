"""Security audit trail: recording and querying.

Events are recorded only for applications with the AUDIT service enabled. Recording is
best-effort: a failure to write an audit row is logged and never fails the caller's request.
Never put secrets, OTP codes, passwords or tokens in `details`.
"""

import logging
from contextlib import contextmanager
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from alzando_authorization.models import ApplicationService, AuditEvent
from alzando_authorization.rate_limit import client_ip
from alzando_authorization.service import ServiceError

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


def mask_identifier(identifier: str) -> str:
    """Return a non-reversible-looking form of an email/identifier for audit details."""
    value = identifier.strip().lower()
    local, sep, domain = value.partition("@")
    if not sep:
        return value[:1] + "***" if value else ""
    return f"{local[:1]}***@{domain}"


def audit_enabled(db: Session, application_id: str) -> bool:
    return bool(db.scalar(select(ApplicationService.enabled).where(
        ApplicationService.application_id == application_id,
        ApplicationService.service_code == "AUDIT",
    )))


class AuditScope:
    """Mutable holder the handler can fill in while the audited operation runs."""

    def __init__(self, account_reference: str | None, details: dict[str, Any] | None):
        self.account_reference = account_reference
        self.details: dict[str, Any] = dict(details or {})


def record_event(
    db: Session,
    request: Request,
    application_id: str,
    event_type: str,
    outcome: str,
    *,
    account_reference: str | None = None,
    error_code: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    try:
        if not audit_enabled(db, application_id):
            return
        db.add(AuditEvent(
            application_id=application_id,
            event_type=event_type,
            outcome=outcome,
            error_code=error_code,
            account_reference=account_reference,
            actor=getattr(request.state, "client_id", None),
            request_id=getattr(request.state, "request_id", None),
            ip_address=client_ip(request),
            details=details or {},
        ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to record audit event %s.", event_type)


@contextmanager
def audited(
    db: Session,
    request: Request,
    application_id: str,
    event_type: str,
    *,
    account_reference: str | None = None,
    details: dict[str, Any] | None = None,
):
    """Record SUCCESS when the block finishes, or FAILURE (with error code) on ServiceError."""
    scope = AuditScope(account_reference, details)
    try:
        yield scope
    except ServiceError as exc:
        record_event(
            db, request, application_id, event_type, "FAILURE",
            account_reference=scope.account_reference, error_code=exc.code, details=scope.details,
        )
        raise
    record_event(
        db, request, application_id, event_type, "SUCCESS",
        account_reference=scope.account_reference, details=scope.details,
    )


def list_events(
    db: Session,
    application_id: str,
    *,
    event_type: str | None,
    outcome: str | None,
    account_reference: str | None,
    limit: int,
    cursor: str | None,
) -> dict:
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    statement = select(AuditEvent).where(AuditEvent.application_id == application_id)
    if event_type:
        statement = statement.where(AuditEvent.event_type == event_type)
    if outcome:
        statement = statement.where(AuditEvent.outcome == outcome)
    if account_reference:
        statement = statement.where(AuditEvent.account_reference == account_reference)
    if cursor:
        try:
            statement = statement.where(AuditEvent.id < int(cursor))
        except ValueError:
            raise ServiceError("INVALID_CURSOR", "Pagination cursor is invalid.", 422) from None
    rows = db.scalars(statement.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()
    page = rows[:limit]
    return {
        "events": [
            {
                "event_id": row.id,
                "event_type": row.event_type,
                "outcome": row.outcome,
                "error_code": row.error_code,
                "account_reference": row.account_reference,
                "actor": row.actor,
                "request_id": row.request_id,
                "ip_address": row.ip_address,
                "details": row.details,
                "created_at": row.created_at.isoformat(),
            }
            for row in page
        ],
        "next_cursor": str(page[-1].id) if len(rows) > limit else None,
    }
