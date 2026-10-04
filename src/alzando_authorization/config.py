from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "production"
    database_url: str = "postgresql+psycopg://alzando:alzando_dev@localhost:5432/alzando_authz"
    token_issuer: str = "https://auth.alzando.local"
    token_audience: str = "alzando-authorization-service"
    access_token_ttl_seconds: int = 300
    refresh_token_ttl_seconds: int = 2_592_000
    authentication_grant_ttl_seconds: int = 300
    jwt_private_key_file: str | None = None
    jwt_public_key_file: str | None = None
    challenge_hmac_secret: str | None = None
    password_recovery_ttl_seconds: int = 300
    password_recovery_resend_interval_seconds: int = 60
    email_verification_ttl_seconds: int = 600
    phone_verification_ttl_seconds: int = 600
    otp_ttl_seconds: int = 300
    otp_resend_interval_seconds: int = 60
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_starttls: bool = True


settings = Settings()
