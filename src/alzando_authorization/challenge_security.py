import hashlib
import hmac

from alzando_authorization.config import settings
from alzando_authorization.service import ServiceError


def challenge_secret() -> bytes:
    if settings.challenge_hmac_secret:
        secret = settings.challenge_hmac_secret.encode("utf-8")
        if settings.app_env.lower() != "development" and len(secret) < 32:
            raise ServiceError("SERVICE_UNAVAILABLE", "Challenge processing is not configured.", 503)
        return secret
    if settings.app_env.lower() == "development":
        return b"development-only-alzando-recovery-hmac-key"
    raise ServiceError("SERVICE_UNAVAILABLE", "Challenge processing is not configured.", 503)


def code_digest(secret: bytes, application_id: str, reference: str, code: str) -> str:
    payload = f"{application_id}:{reference}:{code}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()
