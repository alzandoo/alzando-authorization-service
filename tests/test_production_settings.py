import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from alzando_authorization.config import Settings


def create_private_key_file(tmp_path, key_size=2048):
    """Generate a temporary RSA private key for configuration tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    key_path = tmp_path / "private.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return str(key_path)


def test_production_rejects_dev_identity_header():
    with pytest.raises(
        ValidationError,
        match="ALLOW_DEV_IDENTITY_HEADER",
    ):
        Settings(
            app_env="production",
            allow_dev_identity_header=True,
            jwt_private_key_file="/app/secrets/private.pem",
            challenge_hmac_secret="x" * 32,
        )


def test_production_requires_jwt_private_key():
    with pytest.raises(
        ValidationError,
        match="JWT_PRIVATE_KEY_FILE",
    ):
        Settings(
            app_env="production",
            allow_dev_identity_header=False,
            challenge_hmac_secret="x" * 32,
        )


def test_production_requires_hmac_secret():
    with pytest.raises(
        ValidationError,
        match="CHALLENGE_HMAC_SECRET",
    ):
        Settings(
            app_env="production",
            allow_dev_identity_header=False,
            jwt_private_key_file="/app/secrets/private.pem",
        )


def test_production_rejects_short_hmac_secret():
    with pytest.raises(
        ValidationError,
        match="at least 32 characters",
    ):
        Settings(
            app_env="production",
            allow_dev_identity_header=False,
            jwt_private_key_file="/app/secrets/private.pem",
            challenge_hmac_secret="too-short",
        )


def test_production_settings_are_valid(tmp_path):
    key_path = create_private_key_file(tmp_path)

    settings = Settings(
        app_env="production",
        allow_dev_identity_header=False,
        jwt_private_key_file=key_path,
        challenge_hmac_secret="x" * 32,
    )

    assert settings.app_env == "production"
    assert settings.allow_dev_identity_header is False
    assert settings.jwt_private_key_file == key_path


def test_production_rejects_missing_private_key_file(tmp_path):
    missing_key_path = tmp_path / "missing.pem"

    with pytest.raises(
        ValidationError,
        match="readable, valid",
    ):
        Settings(
            app_env="production",
            jwt_private_key_file=str(missing_key_path),
            challenge_hmac_secret="x" * 32,
        )


def test_production_rejects_invalid_private_key_file(tmp_path):
    key_path = tmp_path / "invalid.pem"
    key_path.write_text("not a valid PEM private key", encoding="utf-8")

    with pytest.raises(
        ValidationError,
        match="readable, valid",
    ):
        Settings(
            app_env="production",
            jwt_private_key_file=str(key_path),
            challenge_hmac_secret="x" * 32,
        )


def test_production_rejects_non_rsa_private_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "ed25519.pem"

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    with pytest.raises(
        ValidationError,
        match="must contain an RSA private key",
    ):
        Settings(
            app_env="production",
            jwt_private_key_file=str(key_path),
            challenge_hmac_secret="x" * 32,
        )


def test_production_rejects_weak_rsa_private_key(tmp_path):
    key_path = create_private_key_file(tmp_path, key_size=1024)

    with pytest.raises(
        ValidationError,
        match="at least 2048 bits",
    ):
        Settings(
            app_env="production",
            jwt_private_key_file=key_path,
            challenge_hmac_secret="x" * 32,
        )
