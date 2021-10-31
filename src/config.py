import os
from datetime import timedelta

from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env")
load_dotenv(dotenv_path)


class Settings:
    """Project configuration."""

    API_URL: str = os.getenv("API_URL", "http://auth:5000")
    APP_NAME: str = os.getenv("APP_NAME", "Auth service")
    DEBUG: bool = bool(int(os.getenv("DEBUG", 0)))
    PROPAGATE_EXCEPTIONS: bool = bool(int(os.getenv("PROPAGATE_EXCEPTIONS", 1)))

    SECRET_KEY: str = os.getenv("SECRET_KEY")
    SECURITY_PASSWORD_SALT: str = os.getenv("SECURITY_PASSWORD_SALT")
    SECURITY_SEND_REGISTER_EMAIL: bool = bool(
        int(os.getenv("SECURITY_SEND_REGISTER_EMAIL", 0))
    )

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(
        hours=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 1))
    )
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(
        hours=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 24))
    )

    SQLALCHEMY_DATABASE_URI: str = os.getenv("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = bool(
        int(os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS", 0))
    )


class RedisSettings:
    REDIS_HOST: str = os.getenv("REDIS_HOST")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT"))
    REDIS_DB: int = int(os.getenv("REDIS_DB"))
