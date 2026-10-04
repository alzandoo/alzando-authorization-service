from sqlalchemy import select
from sqlalchemy.orm import Session

from alzando_authorization.models import ApplicationService, AuthenticationAccount


def activate_when_required_channels_are_verified(
    db: Session, application_id: str, account: AuthenticationAccount
) -> None:
    required_services = set(db.scalars(select(ApplicationService.service_code).where(
        ApplicationService.application_id == application_id,
        ApplicationService.enabled.is_(True),
        ApplicationService.service_code.in_(["EMAIL_VERIFICATION", "PHONE_VERIFICATION"]),
    )).all())
    if "EMAIL_VERIFICATION" in required_services and not account.email_verified:
        return
    if "PHONE_VERIFICATION" in required_services and not account.phone_verified:
        return
    account.status = "ACTIVE"
