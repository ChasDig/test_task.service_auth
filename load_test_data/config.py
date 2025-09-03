from dotenv import find_dotenv
from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PATH = find_dotenv()


class Settings(BaseSettings):
    """Конфигурации - Базы Данных."""

    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # PostgresDB
    pg_drivername: str = "postgresql+asyncpg"
    pg_database: str = Field(default="auth_db", alias="AUTH_POSTGRES_DB")
    pg_username: str = Field(
        default="auth_user",
        alias="AUTH_POSTGRES_USER",
    )
    pg_password: str = Field(default="auth_pass_123", alias="AUTH_POSTGRES_PASSWORD")
    pg_host: str = Field(default="127.0.0.1", alias="POSTGRES_HOST")
    pg_port: int = Field(default=5432, alias="POSTGRES_PORT")

    @computed_field
    @property
    def pg_url_connection(self) -> str:
        return (
            f"postgresql://{self.pg_username}:{self.pg_password}@"
            f"{self.pg_host}:{self.pg_port}/{self.pg_database}"
        )


config = Settings()
