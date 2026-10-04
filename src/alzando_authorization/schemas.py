from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InitialApplicationConfiguration(BaseModel):
    enabled_services: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("enabled_services")
    @classmethod
    def normalize_service_codes(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().upper() for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Service codes must be unique.")
        return normalized


class RegisterApplication(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    application_type: Literal["ALZANDO_OWNED", "EXTERNAL", "VENDOR"]
    owner: dict[str, Any] = Field(default_factory=dict)
    client_type: Literal["PUBLIC", "CONFIDENTIAL"]
    configuration: InitialApplicationConfiguration = Field(default_factory=InitialApplicationConfiguration)


class UpdateApplication(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    owner: dict[str, Any] | None = None
    status: Literal["ACTIVE", "SUSPENDED"] | None = None


class ApplicationServiceSetting(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    service_code: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    enabled: bool
    configuration: dict[str, Any] = Field(default_factory=dict)


class ReplaceApplicationServices(BaseModel):
    services: list[ApplicationServiceSetting] = Field(max_length=100)

    @field_validator("services")
    @classmethod
    def require_unique_services(cls, values: list[ApplicationServiceSetting]) -> list[ApplicationServiceSetting]:
        codes = [value.service_code.upper() for value in values]
        if len(set(codes)) != len(codes):
            raise ValueError("Service codes must be unique.")
        return values


class SignupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    phone: str | None = Field(default=None, min_length=8, max_length=16, pattern=r"^\+[1-9][0-9]{7,14}$")
    display_name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("phone", mode="before")
    @classmethod
    def normalize_phone(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class LoginRequest(BaseModel):
    method: Literal["PASSWORD"] = "PASSWORD"
    identifier: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class PasswordRecoveryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(min_length=3, max_length=320)


class PasswordResetRequest(BaseModel):
    recovery_reference: str = Field(min_length=8, max_length=96, pattern=r"^rcv_[A-Za-z0-9_-]+$")
    verification_code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    new_password: str = Field(min_length=12, max_length=128)


class EmailVerificationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    verification_reference: str = Field(
        min_length=8, max_length=96, pattern=r"^ver_[A-Za-z0-9_-]+$"
    )
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class PhoneVerificationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    verification_reference: str = Field(
        min_length=8, max_length=96, pattern=r"^ver_[A-Za-z0-9_-]+$"
    )
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class OtpRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    purpose: Literal["LOGIN", "VERIFICATION", "MFA", "RECOVERY"]
    channel: Literal["EMAIL", "SMS"]
    account_reference: str = Field(min_length=8, max_length=96, pattern=r"^acct_[A-Za-z0-9_-]+$")


class OtpVerifyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    challenge_reference: str = Field(min_length=8, max_length=96, pattern=r"^otp_[A-Za-z0-9_-]+$")
    otp: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class MfaChallengeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    authentication_reference: str = Field(min_length=8, max_length=96, pattern=r"^ath_[A-Za-z0-9_-]+$")
    channel: Literal["EMAIL", "SMS"] = "EMAIL"


class MfaVerifyRequest(OtpVerifyRequest):
    pass


class IssueUserTokenRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    authentication_reference: str = Field(min_length=8, max_length=96, pattern=r"^ath_[A-Za-z0-9_-]+$")


class RefreshUserTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=160, pattern=r"^rft_[A-Za-z0-9_-]+$")


class RevokeUserTokenRequest(RefreshUserTokenRequest):
    pass


class CreateRole(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class CreatePermission(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    key: str = Field(min_length=3, max_length=150, pattern=r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$")
    description: str | None = Field(default=None, max_length=500)
    resource: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)


class ReplacePermissions(BaseModel):
    permission_ids: list[str] = Field(max_length=500)


class ReplaceUserRoles(BaseModel):
    role_ids: list[str] = Field(max_length=500)


class ResourceContext(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    type: str = Field(min_length=1, max_length=100)
    id: str = Field(min_length=1, max_length=200)


class AuthorizationCheck(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    user_reference: str = Field(min_length=1, max_length=200)
    permission: str = Field(min_length=3, max_length=150)
    resource: ResourceContext | None = None


class ErrorDetail(BaseModel):
    code: str
    message: str


class ApiResponse(BaseModel):
    success: bool
    status: str
    data: dict | None
    error: ErrorDetail | None
    request_id: str
