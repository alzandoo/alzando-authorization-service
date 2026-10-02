from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "production"
    database_url: str = "postgresql+psycopg://alzando:alzando_dev@localhost:5432/alzando_authz"
    token_issuer: str = "https://auth.alzando.local"
    token_audience: str = "alzando-authorization-service"
    access_token_ttl_seconds: int = 300
    jwt_private_key_file: str | None = None
    jwt_public_key_file: str | None = None


settings = Settings()
