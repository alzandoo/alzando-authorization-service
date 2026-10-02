from pydantic import BaseModel, ConfigDict, Field, field_validator


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
