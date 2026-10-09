import pytest
from pydantic import ValidationError

from alzando_authorization.config import Settings


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


def test_production_settings_are_valid():
    settings = Settings(
        app_env="production",
        allow_dev_identity_header=False,
        jwt_private_key_file="/app/secrets/private.pem",
        challenge_hmac_secret="x" * 32,
    )

    assert settings.app_env == "production"
    assert settings.allow_dev_identity_header is False