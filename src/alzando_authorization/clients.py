import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy.orm import Session

from alzando_authorization.models import ApplicationClient

_password_hasher = PasswordHasher()


def create_confidential_client(db: Session, application_id: str, scopes: list[str]) -> tuple[str, str]:
    client_id = f"client_{secrets.token_urlsafe(18)}"
    client_secret = f"secret_{secrets.token_urlsafe(36)}"
    client = ApplicationClient(
        client_id=client_id,
        application_id=application_id,
        client_secret_hash=_password_hasher.hash(client_secret),
        scopes=sorted(set(scopes)),
        is_active=True,
    )
    db.add(client)
    db.commit()
    return client_id, client_secret


def verify_client_secret(client: ApplicationClient | None, candidate: str) -> bool:
    if client is None or not client.is_active:
        return False
    try:
        return _password_hasher.verify(client.client_secret_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
