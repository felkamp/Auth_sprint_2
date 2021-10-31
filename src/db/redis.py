import redis
from flask import Flask

from src.config import RedisSettings

redis_db = redis.Redis(
    host=RedisSettings.REDIS_HOST,
    port=RedisSettings.REDIS_PORT,
    db=RedisSettings.REDIS_DB,
)


def init_redis_db(app: Flask):
    if not hasattr(app, "redis_db"):
        app.redis_db = redis_db
    return app.redis_db
