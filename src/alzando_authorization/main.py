from collections.abc import Callable
from functools import lru_cache
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import text
from sqlalchemy.orm import Session
import jwt

from alzando_authorization.config import settings
from alzando_authorization.clients import verify_client_secret
from alzando_authorization.database import engine, get_db
from alzando_authorization.models import ApplicationClient
from alzando_authorization.schemas import (
    AuthorizationCheck,
    CreatePermission,
    CreateRole,
    ReplacePermissions,
    ReplaceUserRoles,
)
from alzando_authorization.tokens import AccessTokenService
from alzando_authorization.service import (
    ServiceError,
    check_permission,
    create_permission,
    create_role,
    replace_role_permissions,
    replace_user_roles,
)


@lru_cache(maxsize=1)
def token_service() -> AccessTokenService:
    # Keep the development signing key stable for the lifetime of this process.
    return AccessTokenService(settings)


def create_app() -> FastAPI:
    app = FastAPI(title="Alzando Authorization Service", version="0.1.0")
    basic_auth = HTTPBasic(auto_error=False)

    @app.middleware("http")
    async def context_middleware(request: Request, call_next: Callable):
        request.state.request_id = f"req_{uuid4().hex}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def require_scope(required_scope: str):
        def dependency(request: Request) -> str:
            # Development-only identity simulation for quick local API exploration.
            if settings.app_env.lower() == "development":
                application_id = request.headers.get("X-Dev-Application-Id")
                if application_id:
                    return application_id

            header = request.headers.get("Authorization", "")
            scheme, _, credential = header.partition(" ")
            if scheme.lower() != "bearer" or not credential:
                raise ServiceError("UNAUTHENTICATED", "A valid Bearer access token is required.", 401)
            try:
                claims = token_service().verify(credential)
            except (jwt.PyJWTError, ValueError, OSError, RuntimeError):
                raise ServiceError("UNAUTHENTICATED", "Access token is invalid or expired.", 401) from None
            scopes = set(claims.get("scope", "").split())
            if required_scope not in scopes:
                raise ServiceError("FORBIDDEN", "The access token does not grant the required scope.", 403)
            return claims["application_id"]

        return dependency

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

    @app.post("/oauth2/token")
    def issue_token(
        request: Request,
        grant_type: str = Form(...),
        scope: str | None = Form(default=None),
        credentials: HTTPBasicCredentials | None = Depends(basic_auth),
        db: Session = Depends(get_db),
    ):
        def oauth_error(error: str, status_code: int):
            response = JSONResponse(status_code=status_code, content={"error": error})
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Request-ID"] = request.state.request_id
            return response

        if grant_type != "client_credentials":
            return oauth_error("unsupported_grant_type", 400)
        if credentials is None:
            return oauth_error("invalid_client", 401)
        client = db.get(ApplicationClient, credentials.username)
        if not verify_client_secret(client, credentials.password):
            return oauth_error("invalid_client", 401)

        granted_scopes = set(client.scopes)
        requested_scopes = set(scope.split()) if scope else granted_scopes
        if not requested_scopes or not requested_scopes.issubset(granted_scopes):
            return oauth_error("invalid_scope", 400)
        access_token = token_service().issue(
            client.client_id, client.application_id, sorted(requested_scopes)
        )
        response = JSONResponse(content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_seconds,
            "scope": " ".join(sorted(requested_scopes)),
        })
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.post("/api/v1/authorization/roles", status_code=201)
    def post_role(
        body: CreateRole,
        request: Request,
        application_id: str = Depends(require_scope("authorization:manage")),
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
        application_id: str = Depends(require_scope("authorization:manage")),
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
        application_id: str = Depends(require_scope("authorization:manage")),
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
        application_id: str = Depends(require_scope("authorization:manage")),
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
        application_id: str = Depends(require_scope("authorization:check")),
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
