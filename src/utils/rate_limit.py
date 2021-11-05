import datetime
from functools import wraps
from http import HTTPStatus

from flask import jsonify, request
from loguru import logger

from src.db.redis import redis_db


def rate_limit(limit=20, interval=60):
    """Rate limit for API endpoints.

    If the user has exceeded the limit, then return the response 429.
    """

    def rate_limit_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            now = datetime.datetime.now()
            key = f"{request.remote_addr}:{now.minute}"

            current_request_count = redis_db.get(key)

            if current_request_count and int(current_request_count) > limit:
                logger.info(f"Hitting rate limit: {key}")
                resp = jsonify(
                    {
                        "code": HTTPStatus.TOO_MANY_REQUESTS,
                        "message": f"Too many requests. "
                        f"Limit {limit} in {interval} seconds",
                    }
                )
                resp.status_code = HTTPStatus.TOO_MANY_REQUESTS

                return resp
            else:
                pipe = redis_db.pipeline()
                pipe.incr(key, 1)
                pipe.expire(key, interval + 1)
                pipe.execute()

                return f(*args, **kwargs)

        return wrapper

    return rate_limit_decorator
