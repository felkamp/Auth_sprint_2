import uuid
from http import HTTPStatus

from flask import Blueprint, abort
from flask_restx import Namespace, Resource, reqparse

from src.db.redis import redis_db
from src.utils.rate_limit import rate_limit
from src.utils.utils import get_simple_math_problem
from src.constants import KEY_PREFIX_CAPTCHA

security = Blueprint("security", __name__)
api = Namespace(name="security", description="API for security service")


@api.route("/captcha")
class Captcha(Resource):
    @rate_limit()
    def get(self):
        """Get simple math problem."""
        problem_id = str(uuid.uuid4())
        problem, answer = get_simple_math_problem()
        redis_db.setex(name=KEY_PREFIX_CAPTCHA.format(id=problem_id), time=60 * 5, value=answer)
        return {"id": problem_id, "math_problem": problem}


captcha_post_parser = reqparse.RequestParser()
captcha_post_parser.add_argument("problem_id", required=True, location="form")
captcha_post_parser.add_argument("user_answer", required=True, location="form")


@api.route("/check_captcha")
class Captcha(Resource):
    @rate_limit()
    def post(self):
        """Check user answer for math problem."""
        args = captcha_post_parser.parse_args()
        problem_id = args.get("problem_id")
        user_answer = args.get("user_answer")

        if not (real_answer := redis_db.get(KEY_PREFIX_CAPTCHA.format(id=problem_id))):
            abort(HTTPStatus.NOT_FOUND)

        msg = "ok" if str(user_answer) == str(real_answer.decode("utf-8")) else "error"
        redis_db.delete(problem_id)

        return {"msg": msg}
