from collections.abc import Callable
from functools import lru_cache
from uuid import UUID, uuid4

import jwt
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, Form, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from alzando_authorization.config import settings
from alzando_authorization.clients import add_application_client, verify_client_secret
from alzando_authorization.authentication import (
    login as authenticate_user,
    signup as create_authentication_account,
)
from alzando_authorization.password_recovery import (
    complete_password_reset,
    request_password_recovery,
)
from alzando_authorization.email_delivery import send_configured_email
from alzando_authorization.audit import audited, list_events, mask_identifier
from alzando_authorization.email_verification import resend_email_verification, verify_email
from alzando_authorization.phone_verification import resend_phone_verification, verify_phone
from alzando_authorization.rate_limit import RateLimiter, client_ip
from alzando_authorization.scopes import SCOPE_TO_SERVICE
from alzando_authorization.otp import request_otp, verify_otp
from alzando_authorization.database import engine, get_db
from alzando_authorization.models import (
    Application,
    ApplicationClient,
    ApplicationService,
    AuthenticationAccount,
    AuthenticationGrant,
    Service,
    utc_now,
)
from alzando_authorization.schemas import (
    AuthorizationCheck,
    CreatePermission,
    CreateRole,
    RegisterApplication,
    ReplaceApplicationServices,
    ReplacePermissions,
    ReplaceUserRoles,
    LoginRequest,
    PasswordRecoveryRequest,
    PasswordResetRequest,
    EmailVerificationRequest,
    PhoneVerificationRequest,
    ResendVerificationRequest,
    OtpRequest,
    OtpVerifyRequest,
    MfaChallengeRequest,
    MfaVerifyRequest,
    IssueUserTokenRequest,
    RefreshUserTokenRequest,
    RevokeUserTokenRequest,
    SignupRequest,
    UpdateApplication,
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
from alzando_authorization.registry import (
    application_details,
    list_services,
    register_application,
    replace_application_services,
    update_application,
)
from alzando_authorization.user_tokens import (
    issue_user_tokens,
    refresh_user_tokens,
    revoke_user_token,
)


@lru_cache(maxsize=1)
def token_service() -> AccessTokenService:
    # Keep the development signing key stable for the lifetime of this process.
    return AccessTokenService(settings)


def create_app() -> FastAPI:
    app = FastAPI(title="Alzando Authorization Service", version="0.1.0")
    basic_auth = HTTPBasic(auto_error=False)
    service_scopes = SCOPE_TO_SERVICE
    limiter = RateLimiter()

    def throttle(request: Request, bucket: str) -> None:
        limiter.enforce(
            f"ip:{bucket}:{client_ip(request)}", settings.rate_limit_ip_per_minute, 60
        )

    def throttle_identifier(request: Request, bucket: str, application_id: str, identifier: str) -> None:
        limiter.enforce(
            f"id:{bucket}:{application_id}:{identifier.strip().lower()}:{client_ip(request)}",
            settings.rate_limit_identifier_attempts,
            settings.rate_limit_identifier_window_seconds,
        )

    @app.middleware("http")
    async def context_middleware(request: Request, call_next: Callable):
        request.state.request_id = f"req_{uuid4().hex}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def require_scope(required_scope: str):
        def dependency(request: Request, db: Session = Depends(get_db)) -> str:
            application_id = None
            # Development-only identity simulation for quick local API exploration.
            if settings.app_env.lower() == "development" and settings.allow_dev_identity_header:
                dev_application_id = request.headers.get("X-Dev-Application-Id")
                if dev_application_id and (
                    required_scope != "platform:manage" or dev_application_id == "alzando_platform"
                ):
                    application_id = dev_application_id
                    request.state.client_id = "dev-identity"

            if application_id is None:
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
                application_id = claims["application_id"]
                request.state.client_id = claims.get("client_id")

            if required_scope == "platform:manage":
                if application_id != "alzando_platform":
                    raise ServiceError("FORBIDDEN", "Platform management access is required.", 403)
                return application_id

            if application_id == "alzando_platform":
                raise ServiceError("FORBIDDEN", "Platform credentials cannot act as an application client.", 403)
            application = db.get(Application, application_id)
            if application is None:
                raise ServiceError("APPLICATION_NOT_FOUND", "Application is not registered.", 403)
            if application.status != "ACTIVE":
                raise ServiceError("APPLICATION_INACTIVE", "Application is not active.", 403)
            service_code = service_scopes.get(required_scope)
            if service_code:
                enabled = db.scalar(select(ApplicationService.enabled).where(
                    ApplicationService.application_id == application_id,
                    ApplicationService.service_code == service_code,
                ))
                if not enabled:
                    raise ServiceError("SERVICE_NOT_ENABLED", f"{service_code.title()} is not enabled for this application.", 403)
            return application_id

        return dependency

    @app.exception_handler(ServiceError)
    async def service_error_handler(request: Request, exc: ServiceError):
        response = JSONResponse(status_code=exc.http_status, content={
            "success": False,
            "status": exc.code,
            "data": None,
            "error": {"code": exc.code, "message": exc.message},
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex}"),
        })
        for name, value in exc.headers.items():
            response.headers[name] = value
        if request.url.path.startswith(("/api/v1/auth/", "/api/v1/tokens")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        response = JSONResponse(status_code=422, content={
            "success": False,
            "status": "INVALID_REQUEST",
            "data": None,
            "error": {"code": "INVALID_REQUEST", "message": "Request validation failed."},
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex}"),
        })
        if request.url.path.startswith(("/api/v1/auth/", "/api/v1/tokens")):
            response.headers["Cache-Control"] = "no-store"
        return response

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
        throttle(request, "oauth_token")

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
        if client.application_id != "alzando_platform":
            application = db.get(Application, client.application_id)
            if application is None or application.status != "ACTIVE":
                return oauth_error("invalid_client", 401)

        granted_scopes = set(client.scopes)
        requested_scopes = set(scope.split()) if scope else granted_scopes
        if not requested_scopes or not requested_scopes.issubset(granted_scopes):
            return oauth_error("invalid_scope", 400)
        requested_services = {
            service_scopes[requested_scope]
            for requested_scope in requested_scopes
            if requested_scope in service_scopes
        }
        for service_code in requested_services:
            service_enabled = db.scalar(select(ApplicationService.enabled).where(
                ApplicationService.application_id == client.application_id,
                ApplicationService.service_code == service_code,
            ))
            if not service_enabled:
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

    @app.post("/api/v1/applications", status_code=201)
    def post_application(
        body: RegisterApplication,
        request: Request,
        response: Response,
        _: str = Depends(require_scope("platform:manage")),
        db: Session = Depends(get_db),
    ):
        application, client, client_secret = register_application(db, body)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return success(request, "APPLICATION_REGISTERED", {
            "application_id": application.application_id,
            "name": application.name,
            "status": application.status,
            "client": {
                "client_id": client.client_id,
                "client_type": client.client_type,
                "client_secret": client_secret,
                "scopes": client.scopes,
            },
            "secret_notice": "The client secret is shown once; save it securely." if client_secret else None,
        })

    @app.get("/api/v1/applications/{application_id}")
    def get_application(
        application_id: str,
        request: Request,
        _: str = Depends(require_scope("platform:manage")),
        db: Session = Depends(get_db),
    ):
        return success(request, "OK", application_details(db, application_id))

    @app.patch("/api/v1/applications/{application_id}")
    def patch_application(
        application_id: str,
        body: UpdateApplication,
        request: Request,
        _: str = Depends(require_scope("platform:manage")),
        db: Session = Depends(get_db),
    ):
        changes = body.model_dump(exclude_unset=True)
        if not changes:
            raise ServiceError("INVALID_REQUEST", "At least one application field must be provided.", 422)
        if any(changes.get(field) is None for field in ("name", "status", "owner") if field in changes):
            raise ServiceError("INVALID_REQUEST", "Name, status, and owner cannot be null.", 422)
        with audited(
            db, request, application_id, "APPLICATION_UPDATED", details={"fields": sorted(changes)}
        ):
            application = update_application(db, application_id, changes)
        return success(request, "APPLICATION_UPDATED", {
            "application_id": application.application_id,
            "name": application.name,
            "description": application.description,
            "owner": application.owner,
            "status": application.status,
        })

    @app.get("/api/v1/services")
    def get_services(
        request: Request,
        _: str = Depends(require_scope("platform:manage")),
        db: Session = Depends(get_db),
    ):
        return success(request, "OK", {"services": [
            {"service_code": service.service_code, "name": service.name,
             "description": service.description, "service_type": service.service_type}
            for service in list_services(db)
        ]})

    @app.put("/api/v1/applications/{application_id}/services")
    def put_application_services(
        application_id: str,
        body: ReplaceApplicationServices,
        request: Request,
        _: str = Depends(require_scope("platform:manage")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "platform")
        with audited(db, request, application_id, "APPLICATION_SERVICES_UPDATED"):
            count = replace_application_services(db, application_id, body)
        return success(request, "CONFIGURATION_UPDATED", {
            "application_id": application_id,
            "services_updated": count,
        })

    @app.post("/api/v1/auth/signup", status_code=201)
    def post_signup(
        body: SignupRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        application_id: str = Depends(require_scope("authentication:signup")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "signup")
        with audited(
            db, request, application_id, "ACCOUNT_SIGNUP", details={"identifier": mask_identifier(body.email)}
        ) as event:
            result = create_authentication_account(db, application_id, body)
            event.account_reference = result["data"]["account_reference"]
        deliveries = result.get("deliveries", [])
        if result.get("delivery"):
            deliveries = [*deliveries, result["delivery"]]
        for delivery in deliveries:
            background_tasks.add_task(send_configured_email, **delivery)
        response.headers["Cache-Control"] = "no-store"
        return success(request, result["status"], result["data"])

    @app.post("/api/v1/auth/login")
    def post_login(
        body: LoginRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:login")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "login")
        throttle_identifier(request, "login", application_id, body.identifier)
        with audited(
            db, request, application_id, "AUTH_LOGIN",
            details={"identifier": mask_identifier(body.identifier)},
        ) as event:
            result = authenticate_user(db, application_id, body, failure_tracker=limiter)
            event.account_reference = result["data"].get("account_reference")
            event.details["result"] = result["status"]
        response.headers["Cache-Control"] = "no-store"
        return success(request, result["status"], result["data"])

    @app.post("/api/v1/auth/password/recovery")
    def post_password_recovery(
        body: PasswordRecoveryRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        application_id: str = Depends(require_scope("authentication:recovery")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "recovery")
        throttle_identifier(request, "recovery", application_id, body.identifier)
        with audited(
            db, request, application_id, "PASSWORD_RECOVERY_REQUESTED",
            details={"identifier": mask_identifier(body.identifier)},
        ):
            result = request_password_recovery(db, application_id, body.identifier)
        if result.get("delivery"):
            background_tasks.add_task(send_configured_email, **result["delivery"])
        response.headers["Cache-Control"] = "no-store"
        return success(request, result["status"], result["data"])

    @app.post("/api/v1/auth/password/reset")
    def post_password_reset(
        body: PasswordResetRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:recovery")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "recovery")
        with audited(db, request, application_id, "PASSWORD_RESET"):
            result = complete_password_reset(db, application_id, body)
        response.headers["Cache-Control"] = "no-store"
        return success(request, "PASSWORD_RESET", result)

    @app.post("/api/v1/auth/verify/email")
    def post_verify_email(
        body: EmailVerificationRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:verify")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "verify")
        with audited(db, request, application_id, "EMAIL_VERIFIED"):
            result = verify_email(db, application_id, body.verification_reference, body.code)
        response.headers["Cache-Control"] = "no-store"
        return success(request, "VERIFIED", result)

    def verification_payload(channel: str, result: dict) -> dict:
        return {"channel": channel, **{key: value for key, value in result.items() if key != "delivery"}}

    @app.post("/api/v1/auth/verify/email/resend")
    def post_resend_email_verification(
        body: ResendVerificationRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        application_id: str = Depends(require_scope("authentication:verify")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "verify")
        with audited(
            db, request, application_id, "EMAIL_VERIFICATION_RESENT",
            account_reference=body.account_reference,
        ):
            result = resend_email_verification(db, application_id, body.account_reference)
        if result.get("delivery"):
            background_tasks.add_task(send_configured_email, **result["delivery"])
        response.headers["Cache-Control"] = "no-store"
        return success(request, "VERIFICATION_RESENT", verification_payload("EMAIL", result))

    @app.post("/api/v1/auth/verify/phone/resend")
    def post_resend_phone_verification(
        body: ResendVerificationRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:verify_phone")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "verify")
        with audited(
            db, request, application_id, "PHONE_VERIFICATION_RESENT",
            account_reference=body.account_reference,
        ):
            result = resend_phone_verification(db, application_id, body.account_reference)
        response.headers["Cache-Control"] = "no-store"
        return success(request, "VERIFICATION_RESENT", verification_payload("PHONE", result))

    @app.post("/api/v1/auth/verify/phone")
    def post_verify_phone(
        body: PhoneVerificationRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:verify_phone")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "verify")
        with audited(db, request, application_id, "PHONE_VERIFIED"):
            result = verify_phone(db, application_id, body.verification_reference, body.code)
        response.headers["Cache-Control"] = "no-store"
        return success(request, "VERIFIED", result)

    @app.post("/api/v1/auth/otp/request")
    def post_otp_request(
        body: OtpRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        application_id: str = Depends(require_scope("authentication:otp")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "otp")
        with audited(
            db, request, application_id, "OTP_REQUESTED", account_reference=body.account_reference,
            details={"purpose": body.purpose, "channel": body.channel},
        ):
            result = request_otp(db, application_id, body)
        if result.get("delivery"):
            background_tasks.add_task(send_configured_email, **result["delivery"])
        response.headers["Cache-Control"] = "no-store"
        return success(request, result["status"], result["data"])

    @app.post("/api/v1/auth/otp/verify")
    def post_otp_verify(
        body: OtpVerifyRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:otp")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "otp")
        with audited(db, request, application_id, "OTP_VERIFIED") as event:
            result = verify_otp(db, application_id, body.challenge_reference, body.otp)
            event.account_reference = result.get("account_reference")
            event.details["purpose"] = result.get("purpose")
        response.headers["Cache-Control"] = "no-store"
        return success(request, "VERIFIED", result)

    @app.post("/api/v1/auth/mfa/challenge")
    def post_mfa_challenge(
        body: MfaChallengeRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        application_id: str = Depends(require_scope("authentication:mfa")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "mfa")
        with audited(db, request, application_id, "MFA_CHALLENGE_REQUESTED") as event:
            grant = db.scalar(select(AuthenticationGrant).where(
                AuthenticationGrant.application_id == application_id,
                AuthenticationGrant.authentication_reference == body.authentication_reference,
            ).with_for_update())
            if (
                grant is None or grant.used_at is not None or grant.expires_at <= utc_now()
                or not grant.mfa_required or grant.mfa_verified
            ):
                raise ServiceError("INVALID_AUTHENTICATION_GRANT", "Authentication grant is invalid or expired.", 400)
            account = db.scalar(select(AuthenticationAccount).where(
                AuthenticationAccount.application_id == application_id,
                AuthenticationAccount.account_reference == grant.account_reference,
            ).with_for_update())
            if account is None or account.status != "ACTIVE":
                raise ServiceError("ACCOUNT_UNAVAILABLE", "The account is not active.", 401)
            event.account_reference = grant.account_reference
            result = request_otp(db, application_id, OtpRequest(
                account_reference=grant.account_reference,
                purpose="MFA",
                channel=body.channel,
            ), authentication_reference=grant.authentication_reference)
        if result.get("delivery"):
            background_tasks.add_task(send_configured_email, **result["delivery"])
        response.headers["Cache-Control"] = "no-store"
        return success(request, "MFA_CHALLENGE_CREATED", result["data"])

    @app.post("/api/v1/auth/mfa/verify")
    def post_mfa_verify(
        body: MfaVerifyRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:mfa")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "mfa")
        with audited(db, request, application_id, "MFA_VERIFIED") as event:
            result = verify_otp(
                db, application_id, body.challenge_reference, body.otp, expected_purpose="MFA"
            )
            authentication_reference = result.get("authentication_reference")
            grant = db.scalar(select(AuthenticationGrant).where(
                AuthenticationGrant.application_id == application_id,
                AuthenticationGrant.authentication_reference == authentication_reference,
            ).with_for_update()) if authentication_reference else None
            if (
                grant is None or grant.used_at is not None or grant.expires_at <= utc_now()
                or not grant.mfa_required or grant.account_reference != result["account_reference"]
            ):
                raise ServiceError("INVALID_AUTHENTICATION_GRANT", "Authentication grant is invalid or expired.", 400)
            event.account_reference = result["account_reference"]
            grant.mfa_verified = True
            db.commit()
            result["authentication_reference"] = authentication_reference
        response.headers["Cache-Control"] = "no-store"
        return success(request, "MFA_VERIFIED", result)

    @app.post("/api/v1/tokens")
    def post_user_token(
        body: IssueUserTokenRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:token")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "token")
        with audited(db, request, application_id, "TOKENS_ISSUED") as event:
            data = issue_user_tokens(db, application_id, body.authentication_reference, token_service())
            event.account_reference = data["account_reference"]
            event.details["session_id"] = data["session_id"]
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return success(request, "TOKENS_ISSUED", data)

    @app.post("/api/v1/tokens/refresh")
    def post_user_token_refresh(
        body: RefreshUserTokenRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:token")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "token")
        with audited(db, request, application_id, "TOKENS_REFRESHED") as event:
            data = refresh_user_tokens(db, application_id, body.refresh_token, token_service())
            event.account_reference = data["account_reference"]
            event.details["session_id"] = data["session_id"]
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return success(request, "TOKENS_REFRESHED", data)

    @app.post("/api/v1/tokens/revoke")
    def post_user_token_revoke(
        body: RevokeUserTokenRequest,
        request: Request,
        response: Response,
        application_id: str = Depends(require_scope("authentication:token")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "token")
        with audited(db, request, application_id, "TOKEN_REVOKED"):
            revoke_user_token(db, application_id, body.refresh_token)
        response.headers["Cache-Control"] = "no-store"
        return success(request, "TOKEN_REVOKED", {"revoked": True})

    @app.post("/api/v1/authorization/roles", status_code=201)
    def post_role(
        body: CreateRole,
        request: Request,
        application_id: str = Depends(require_scope("authorization:manage")),
        db: Session = Depends(get_db),
    ):
        with audited(db, request, application_id, "ROLE_CREATED", details={"name": body.name}):
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
        with audited(db, request, application_id, "PERMISSION_CREATED", details={"key": body.key}):
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
        with audited(
            db, request, application_id, "ROLE_PERMISSIONS_SET", details={"role_id": role_id}
        ):
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
        with audited(
            db, request, application_id, "USER_ROLES_SET", details={"user_reference": user_reference}
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

    @app.get("/api/v1/audit/events")
    def get_audit_events(
        request: Request,
        response: Response,
        event_type: str | None = Query(default=None, max_length=64),
        outcome: Literal["SUCCESS", "FAILURE"] | None = None,
        account_reference: str | None = Query(default=None, max_length=96),
        limit: int = Query(default=50, ge=1, le=200),
        cursor: str | None = Query(default=None, max_length=32),
        application_id: str = Depends(require_scope("audit:read")),
        db: Session = Depends(get_db),
    ):
        throttle(request, "audit")
        data = list_events(
            db, application_id, event_type=event_type, outcome=outcome,
            account_reference=account_reference, limit=limit, cursor=cursor,
        )
        response.headers["Cache-Control"] = "no-store"
        return success(request, "OK", data)

    return app


app = create_app()
