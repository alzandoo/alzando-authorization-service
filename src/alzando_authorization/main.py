from collections.abc import Callable
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from alzando_authorization.config import settings
from alzando_authorization.database import engine, get_db
from alzando_authorization.models import Base
from alzando_authorization.schemas import (
    AuthorizationCheck,
    CreatePermission,
    CreateRole,
    ReplacePermissions,
    ReplaceUserRoles,
)
from alzando_authorization.service import (
    ServiceError,
    check_permission,
    create_permission,
    create_role,
    replace_role_permissions,
    replace_user_roles,
)


def create_app() -> FastAPI:
    app = FastAPI(title="Alzando Authorization Service", version="0.1.0")

    @app.middleware("http")
    async def context_middleware(request: Request, call_next: Callable):
        request.state.request_id = f"req_{uuid4().hex}"
        if settings.app_env.lower() == "development":
            # Local-only identity simulation. Production ignores this header.
            request.state.application_id = request.headers.get("X-Dev-Application-Id")
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def get_application_id(request: Request) -> str:
        # A trusted authentication adapter must set this state in production.
        application_id = getattr(request.state, "application_id", None)
        if not application_id:
            raise ServiceError("UNAUTHENTICATED", "Authenticated application context is required.", 401)
        return application_id

    @app.exception_handler(ServiceError)
    async def service_error_handler(request: Request, exc: ServiceError):
        return JSONResponse(status_code=exc.http_status, content={
            "success": False,
            "status": exc.code,
            "data": None,
            "error": {"code": exc.code, "message": exc.message},
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex}"),
        })

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={
            "success": False,
            "status": "INVALID_REQUEST",
            "data": None,
            "error": {"code": "INVALID_REQUEST", "message": "Request validation failed."},
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex}"),
        })

    def success(request: Request, status: str, data: dict):
        return {
            "success": True,
            "status": status,
            "data": data,
            "error": None,
            "request_id": request.state.request_id,
        }

    @app.get("/health/live", include_in_schema=False)
    def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def readiness():
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok"}

    @app.post("/api/v1/authorization/roles", status_code=201)
    def post_role(
        body: CreateRole,
        request: Request,
        application_id: str = Depends(get_application_id),
        db: Session = Depends(get_db),
    ):
        role = create_role(db, application_id, body.name, body.description)
        return success(request, "ROLE_CREATED", {
            "role_id": str(role.id), "name": role.name, "description": role.description,
        })

    @app.post("/api/v1/authorization/permissions", status_code=201)
    def post_permission(
        body: CreatePermission,
        request: Request,
        application_id: str = Depends(get_application_id),
        db: Session = Depends(get_db),
    ):
        permission = create_permission(
            db, application_id, body.key, body.description, body.resource, body.action
        )
        return success(request, "PERMISSION_CREATED", {
            "permission_id": str(permission.id), "key": permission.key,
            "description": permission.description, "resource": permission.resource,
            "action": permission.action,
        })

    @app.put("/api/v1/authorization/roles/{role_id}/permissions")
    def put_role_permissions(
        role_id: str,
        body: ReplacePermissions,
        request: Request,
        application_id: str = Depends(get_application_id),
        db: Session = Depends(get_db),
    ):
        try:
            parsed_role_id = UUID(role_id)
        except ValueError as exc:
            raise ServiceError("INVALID_ROLE_ID", "Role ID is invalid.", 422) from exc
        count = replace_role_permissions(db, application_id, parsed_role_id, body.permission_ids)
        return success(request, "ROLE_PERMISSIONS_UPDATED", {
            "role_id": role_id, "permission_count": count,
        })

    @app.put("/api/v1/authorization/users/{user_reference}/roles")
    def put_user_roles(
        user_reference: str,
        body: ReplaceUserRoles,
        request: Request,
        application_id: str = Depends(get_application_id),
        db: Session = Depends(get_db),
    ):
        count = replace_user_roles(db, application_id, user_reference, body.role_ids)
        return success(request, "USER_ROLES_UPDATED", {
            "user_reference": user_reference, "role_count": count,
        })

    @app.post("/api/v1/authorization/check")
    def post_authorization_check(
        body: AuthorizationCheck,
        request: Request,
        application_id: str = Depends(get_application_id),
        db: Session = Depends(get_db),
    ):
        allowed = check_permission(db, application_id, body.user_reference, body.permission)
        decision = "ALLOWED" if allowed else "DENIED"
        return success(request, decision, {
            "decision": decision,
            "permission": body.permission,
            "resource": body.resource.model_dump() if body.resource else None,
        })

    return app


app = create_app()
