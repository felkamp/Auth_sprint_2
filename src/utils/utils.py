import random
from functools import wraps
from http import HTTPStatus
from uuid import UUID

from flask import abort
from flask_jwt_extended import get_jwt

from src.constants import operators_mapping
from src.models.user import Permission


def is_valid_uuid(uuid, version=4):
    try:
        UUID(uuid, version=version)
    except ValueError:
        return False
    return True


def check_permission(permission: Permission):
    """
    Check user permissions using jwt
    """

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            jwt = get_jwt()
            if jwt.get("perms") and (jwt["perms"] & permission):
                return func(*args, **kwargs)
            return abort(HTTPStatus.FORBIDDEN, "Not enough rights")

        return wrapped

    return decorator


def get_simple_math_problem() -> (str, int):
    num_1 = random.randint(1, 10)
    num_2 = random.randint(1, 10)
    op = random.choice(list(operators_mapping.keys()))

    problem = f"{num_1} {op} {num_2}"
    answer = operators_mapping.get(op)(num_1, num_2)
    return problem, answer
