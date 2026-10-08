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
    # Development-only: lets callers impersonate an application with `X-Dev-Application-Id`.
    # Requires APP_ENV=development AND this explicit flag.
    allow_dev_identity_header: bool = False
    # Rate limiting (per process; see rate_limit.py).
    rate_limit_enabled: bool = True
    rate_limit_ip_per_minute: int = 120
    rate_limit_identifier_attempts: int = 10
    rate_limit_identifier_window_seconds: int = 900
    # Honour X-Forwarded-For (right-most entry) when running behind a trusted proxy.
    trust_proxy_headers: bool = False
    verification_resend_interval_seconds: int = 60
    email_verification_ttl_seconds: int = 600
    phone_verification_ttl_seconds: int = 600
    otp_ttl_seconds: int = 300
    otp_resend_interval_seconds: int = 60
    brevo_api_key: str | None = None
    brevo_from_email: str | None = None
    brevo_from_name: str = "Alzando"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_starttls: bool = True
    


settings = Settings()
