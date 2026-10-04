from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from alzando_authorization.config import Settings


class AccessTokenService:
    def __init__(self, config: Settings):
        self.config = config
        if config.app_env.lower() == "development" and not config.jwt_private_key_file:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
        else:
            if not config.jwt_private_key_file:
                raise RuntimeError("JWT_PRIVATE_KEY_FILE must be configured outside development.")
            self.private_key = serialization.load_pem_private_key(
                Path(config.jwt_private_key_file).read_bytes(), password=None
            )
            if config.jwt_public_key_file:
                self.public_key = serialization.load_pem_public_key(
                    Path(config.jwt_public_key_file).read_bytes()
                )
            else:
                self.public_key = self.private_key.public_key()

    def issue(self, client_id: str, application_id: str, scopes: list[str]) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "iss": self.config.token_issuer,
            "aud": self.config.token_audience,
            "sub": client_id,
            "client_id": client_id,
            "application_id": application_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + timedelta(seconds=self.config.access_token_ttl_seconds),
            "jti": uuid4().hex,
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"typ": "at+jwt"})

    def issue_user(
        self, account_reference: str, application_id: str, session_id: str, mfa_authenticated: bool
    ) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "iss": self.config.token_issuer,
            "aud": self.config.token_audience,
            "sub": account_reference,
            "application_id": application_id,
            "token_use": "user_access",
            "sid": session_id,
            "amr": ["pwd", "otp"] if mfa_authenticated else ["pwd"],
            "iat": now,
            "exp": now + timedelta(seconds=self.config.access_token_ttl_seconds),
            "jti": uuid4().hex,
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"typ": "at+jwt"})

    def verify(self, token: str) -> dict:
        return jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            issuer=self.config.token_issuer,
            audience=self.config.token_audience,
            options={"require": ["iss", "aud", "sub", "client_id", "application_id", "scope", "iat", "exp", "jti"]},
        )
