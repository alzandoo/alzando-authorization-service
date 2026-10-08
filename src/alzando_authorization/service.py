from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alzando_authorization.models import Permission, Role, RolePermission, UserRole


class ServiceError(Exception):
    def __init__(
        self, code: str, message: str, http_status: int, headers: dict[str, str] | None = None
    ):
        super().__init__(code, message, http_status)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.headers = headers or {}


def create_role(db: Session, application_id: str, name: str, description: str | None) -> Role:
    role = Role(application_id=application_id, name=name, description=description)
    db.add(role)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint_name = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint_name == "uq_roles_application_name":
            raise ServiceError("ROLE_ALREADY_EXISTS", "A role with this name already exists.", 409) from exc
        raise
    db.refresh(role)
    return role


def create_permission(
    db: Session, application_id: str, key: str, description: str | None, resource: str, action: str
) -> Permission:
    permission = Permission(
        application_id=application_id, key=key, description=description, resource=resource, action=action
    )
    db.add(permission)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint_name = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint_name == "uq_permissions_application_key":
            raise ServiceError("PERMISSION_ALREADY_EXISTS", "A permission with this key already exists.", 409) from exc
        raise
    db.refresh(permission)
    return permission


def _parse_ids(values: list[str], kind: str) -> list[UUID]:
    if len(set(values)) != len(values):
        raise ServiceError("DUPLICATE_REFERENCE", f"Duplicate {kind} IDs are not allowed.", 422)
    try:
        return [UUID(value) for value in values]
    except ValueError as exc:
        raise ServiceError("INVALID_REFERENCE", f"One or more {kind} IDs are invalid.", 422) from exc


def replace_role_permissions(db: Session, application_id: str, role_id: UUID, values: list[str]) -> int:
    permission_ids = _parse_ids(values, "permission")
    role = db.scalar(select(Role).where(Role.id == role_id, Role.application_id == application_id))
    if role is None:
        raise ServiceError("ROLE_NOT_FOUND", "Role was not found.", 404)
    if permission_ids:
        found_ids = set(db.scalars(select(Permission.id).where(
            Permission.application_id == application_id, Permission.id.in_(permission_ids)
        )).all())
        if found_ids != set(permission_ids):
            raise ServiceError("REFERENCE_NOT_FOUND", "One or more permissions do not exist in this application.", 422)

    db.execute(delete(RolePermission).where(
        RolePermission.application_id == application_id, RolePermission.role_id == role_id
    ))
    db.add_all(RolePermission(application_id=application_id, role_id=role_id, permission_id=permission_id)
               for permission_id in permission_ids)
    db.commit()
    return len(permission_ids)


def replace_user_roles(db: Session, application_id: str, user_reference: str, values: list[str]) -> int:
    role_ids = _parse_ids(values, "role")
    if role_ids:
        found_ids = set(db.scalars(select(Role.id).where(
            Role.application_id == application_id, Role.id.in_(role_ids)
        )).all())
        if found_ids != set(role_ids):
            raise ServiceError("REFERENCE_NOT_FOUND", "One or more roles do not exist in this application.", 422)

    db.execute(delete(UserRole).where(
        UserRole.application_id == application_id,
        UserRole.user_reference == user_reference,
    ))
    db.add_all(UserRole(application_id=application_id, user_reference=user_reference, role_id=role_id)
               for role_id in role_ids)
    db.commit()
    return len(role_ids)


def check_permission(db: Session, application_id: str, user_reference: str, permission_key: str) -> bool:
    statement = (
        select(Permission.id)
        .join(RolePermission, (RolePermission.permission_id == Permission.id)
              & (RolePermission.application_id == Permission.application_id))
        .join(UserRole, (UserRole.role_id == RolePermission.role_id)
              & (UserRole.application_id == RolePermission.application_id))
        .where(
            Permission.application_id == application_id,
            RolePermission.application_id == application_id,
            UserRole.application_id == application_id,
            UserRole.user_reference == user_reference,
            Permission.key == permission_key,
        )
        .limit(1)
    )
    return db.scalar(statement) is not None
