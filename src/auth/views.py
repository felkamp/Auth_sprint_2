from http import HTTPStatus
from typing import Optional

from flask import Blueprint, abort
from flask_jwt_extended import get_jwt, jwt_required
from flask_restx import Namespace, Resource, fields, reqparse
from flask_security.registerable import register_user
from opentracing_decorator import Tracing

from src.models.user import User
from src.services.auth import auth_service
from src.utils.jaeger import jaeger_tracer
from src.utils.rate_limit import rate_limit

auth = Blueprint("auth", __name__)
api = Namespace(name="auth", description="API for auth service")

msg_response_model = api.model(
    "Msg data response",
    {
        "msg": fields.String(
            default="Thank you for registering. Now you can log in to your account."
        )
    },
)

tokens_response_model = api.model(
    "Token data response",
    {
        "access": fields.String(default="JWTTOKENACCESS"),
        "refresh": fields.String(default="JWTTOKENREFRESH"),
    },
)

login_post_parser = reqparse.RequestParser()
login_post_parser.add_argument("email", required=True, help="Email cannot be blank!")
login_post_parser.add_argument(
    "password", required=True, help="Password cannot be blank!"
)
login_post_parser.add_argument("User-Agent", location="headers")

tracing = Tracing(tracer=jaeger_tracer)


@api.route("/login")
class Login(Resource):
    """Endpoint to user login."""

    @tracing.trace(operation_name="Login")
    @rate_limit()
    @api.expect(login_post_parser)
    @api.marshal_with(tokens_response_model, code=HTTPStatus.OK)
    def post(self):
        """Check user credentials and get JWT token for user."""

        args = login_post_parser.parse_args()

        error_message = "Email or password is incorrect"

        email = args.get("email")
        authenticated_user = auth_service.authenticate_user(
            email=email, password=args.get("password")
        )
        if not authenticated_user:
            return abort(HTTPStatus.FORBIDDEN, error_message)

        return auth_service.get_user_tokens(authenticated_user, args.get("User-Agent"))


logout_post_parser = reqparse.RequestParser()
logout_post_parser.add_argument("User-Agent", location="headers")
logout_post_parser.add_argument(
    "is_full", required=False, type=bool, help="Logout from all accounts!"
)


@api.route("/logout")
class Logout(Resource):
    """Endpoint to user logout."""

    @tracing.trace(operation_name="Logout")
    @rate_limit()
    @api.expect(logout_post_parser)
    @api.marshal_with(msg_response_model, code=HTTPStatus.OK)
    @jwt_required()
    def post(self):
        """Logout user with deleting refresh tokens.

        If 'is_full' request param exists, then delete all refresh tokens.
        """
        args = logout_post_parser.parse_args()

        token_payload = get_jwt()

        user_id = token_payload.get("sub")
        user_agent = args.get("User-Agent")
        if args.get("is_full"):
            auth_service.delete_all_refresh_tokens(user_id)
        else:
            auth_service.delete_user_refresh_token(user_id, user_agent)
        return {
            "msg": "Successful logout",
        }


register_post_parser = reqparse.RequestParser()
register_post_parser.add_argument("email", required=True, help="Email cannot be blank!")
register_post_parser.add_argument(
    "password", required=True, help="Password cannot be blank!"
)


@api.route("/register")
class Register(Resource):
    """Endpoint to sign up."""

    @tracing.trace(operation_name="Register")
    @rate_limit()
    @api.expect(register_post_parser)
    @api.marshal_with(msg_response_model, code=HTTPStatus.OK)
    def post(self):
        """Register a new user."""
        args = register_post_parser.parse_args()
        email = args.get("email")
        password = args.get("password")
        if User.query.filter_by(email=email).first():
            return abort(HTTPStatus.BAD_REQUEST, "This email address already exists!")
        register_user(email=email, password=password)
        return {
            "msg": "Thank you for registering. Now you can log in to your account.",
        }


refresh_post_parser = reqparse.RequestParser()
refresh_post_parser.add_argument("User-Agent", location="headers")
refresh_post_parser.add_argument("Authorization", location="headers")


@api.route("/refresh")
class Refresh(Resource):
    """Endpoint to refresh JWT tokens."""

    @tracing.trace(operation_name="Refresh")
    @rate_limit()
    @api.expect(refresh_post_parser)
    @jwt_required(refresh=True)
    @api.marshal_with(tokens_response_model, code=HTTPStatus.OK)
    def post(self):
        """Create new pair of access and refresh JWT tokens for user."""

        args = refresh_post_parser.parse_args()

        user_agent: str = args.get("User-Agent")

        token_payload = get_jwt()
        user_id: str = token_payload.get("sub")

        jwt_tokens: Optional[dict] = auth_service.refresh_jwt_tokens(
            user_id=user_id, user_agent=user_agent
        )

        if not jwt_tokens:
            return abort(HTTPStatus.UNAUTHORIZED, "Authentication Timeout!")
        return jwt_tokens
