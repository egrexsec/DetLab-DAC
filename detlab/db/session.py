import os
from dataclasses import dataclass

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    database_url: str | None = None
    echo: bool = False

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        return cls(
            database_url=os.getenv("DATABASE_URL") or None,
            echo=os.getenv("SQLALCHEMY_ECHO", "false").lower() in {"1", "true", "yes", "on"},
        )

    @property
    def has_database(self) -> bool:
        return bool(self.database_url)


def build_engine(config: DatabaseConfig) -> Engine:
    if not config.database_url:
        raise ValueError("DATABASE_URL is not configured")

    return create_engine(config.database_url, echo=config.echo)


def build_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)