import secrets
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alzando_authorization.clients import add_application_client
from alzando_authorization.models import Application, ApplicationClient, ApplicationService, Service
from alzando_authorization.schemas import RegisterApplication, ReplaceApplicationServices
from alzando_authorization.service import ServiceError


def register_application(db: Session, request: RegisterApplication) -> tuple[Application, ApplicationClient, str | None]:
    services = db.scalars(select(Service).where(Service.status == "ACTIVE")).all()
    service_by_code = {service.service_code: service for service in services}
    requested = set(request.configuration.enabled_services)
    unknown = requested - service_by_code.keys()
    if unknown:
        raise ServiceError("UNKNOWN_SERVICE", f"Unknown service code(s): {', '.join(sorted(unknown))}.", 422)

    application = Application(
        application_id=f"app_{secrets.token_urlsafe(18)}",
        name=request.name,
        description=request.description,
        application_type=request.application_type,
        owner=request.owner,
        status="ACTIVE",
    )
    db.add(application)
    db.flush()

    for service in services:
        db.add(ApplicationService(
            application_id=application.application_id,
            service_code=service.service_code,
            enabled=service.service_code in requested,
            configuration={},
        ))

    # Service configuration is enforced when a token is issued and again on API calls.
    client_scopes = []
    if "AUTHORIZATION" in requested:
        client_scopes.append("authorization:check")
    if "SIGNUP" in requested:
        client_scopes.append("authentication:signup")
    if "LOGIN" in requested:
        client_scopes.append("authentication:login")
    if "PASSWORD_RECOVERY" in requested:
        client_scopes.append("authentication:recovery")
    if "EMAIL_VERIFICATION" in requested:
        client_scopes.append("authentication:verify")
    if "PHONE_VERIFICATION" in requested:
        client_scopes.append("authentication:verify_phone")
    client, client_secret = add_application_client(
        db, application.application_id, client_scopes, request.client_type
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ServiceError("APPLICATION_REGISTRATION_FAILED", "Application registration could not be completed.", 409) from exc
    db.refresh(application)
    db.refresh(client)
    return application, client, client_secret


def application_details(db: Session, application_id: str) -> dict[str, Any]:
    application = db.get(Application, application_id)
    if application is None:
        raise ServiceError("APPLICATION_NOT_FOUND", "Application was not found.", 404)
    clients = db.scalars(
        select(ApplicationClient).where(ApplicationClient.application_id == application_id)
        .order_by(ApplicationClient.created_at)
    ).all()
    configurations = db.execute(
        select(ApplicationService, Service)
        .join(Service, Service.service_code == ApplicationService.service_code)
        .where(ApplicationService.application_id == application_id)
        .order_by(Service.service_code)
    ).all()
    return {
        "application_id": application.application_id,
        "name": application.name,
        "description": application.description,
        "application_type": application.application_type,
        "owner": application.owner,
        "status": application.status,
        "created_at": application.created_at,
        "updated_at": application.updated_at,
        "clients": [
            {"client_id": client.client_id, "client_type": client.client_type,
             "client_status": "ACTIVE" if client.is_active else "INACTIVE",
             "scopes": client.scopes}
            for client in clients
        ],
        "services": [
            {"service_code": service.service_code, "enabled": config.enabled,
             "configuration": config.configuration}
            for config, service in configurations
        ],
    }


def update_application(db: Session, application_id: str, changes: dict[str, Any]) -> Application:
    application = db.get(Application, application_id)
    if application is None:
        raise ServiceError("APPLICATION_NOT_FOUND", "Application was not found.", 404)
    for key, value in changes.items():
        setattr(application, key, value)
    db.commit()
    db.refresh(application)
    return application


def list_services(db: Session) -> list[Service]:
    return db.scalars(select(Service).where(Service.status == "ACTIVE").order_by(Service.service_type, Service.name)).all()


def replace_application_services(
    db: Session, application_id: str, request: ReplaceApplicationServices
) -> int:
    if db.get(Application, application_id) is None:
        raise ServiceError("APPLICATION_NOT_FOUND", "Application was not found.", 404)

    requested = {item.service_code.upper(): item for item in request.services}
    available = {
        service.service_code
        for service in db.scalars(select(Service).where(Service.status == "ACTIVE")).all()
    }
    unknown = requested.keys() - available
    if unknown:
        raise ServiceError("UNKNOWN_SERVICE", f"Unknown or unavailable service code(s): {', '.join(sorted(unknown))}.", 422)

    db.execute(delete(ApplicationService).where(ApplicationService.application_id == application_id))
    db.add_all(
        ApplicationService(
            application_id=application_id,
            service_code=service.service_code,
            enabled=requested[service.service_code].enabled if service.service_code in requested else False,
            configuration=requested[service.service_code].configuration if service.service_code in requested else {},
        )
        for service in db.scalars(select(Service).order_by(Service.service_code)).all()
    )
    db.commit()
    return len(requested)
