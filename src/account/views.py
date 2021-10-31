from http import HTTPStatus
from typing import Optional

from flask import Blueprint, abort
from flask_jwt_extended import get_jwt, jwt_required
from flask_restx import Api, Resource, reqparse
from flask_security.registerable import register_user

from src.models.user import USER_DATASTORE, User
from src.services.auth import auth_service

account = Blueprint("account", __name__)
api = Api(account)

login_post_parser = reqparse.RequestParser()
login_post_parser.add_argument("email", required=True, help="Email cannot be blank!")
login_post_parser.add_argument(
    "password", required=True, help="Password cannot be blank!"
)
login_post_parser.add_argument("User-Agent", location="headers")


@api.route("/login")
class Login(Resource):
    """Endpoint to user login."""

    @api.expect(login_post_parser)
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
        jwt_tokens = auth_service.get_jwt_tokens(authenticated_user)

        user_agent = args.get("User-Agent")
        auth_service.save_refresh_token_in_redis(jwt_tokens.get("refresh"), user_agent)
        auth_service.create_user_auth_log(
            user_id=authenticated_user.id, device=user_agent
        )

        return jwt_tokens


@api.route("/login_history")
class LoginHistory(Resource):
    """Endpoint to represent user login history."""

    @jwt_required()
    def get(self):
        """Get user login history info."""
        token_payload = get_jwt()
        user_id = token_payload.get("sub")
        user_logs = auth_service.get_auth_user_logs(user_id)
        return user_logs


credentials_change_put = reqparse.RequestParser()
credentials_change_put.add_argument(
    "credential_type", required=True, help="Type to change"
)
credentials_change_put.add_argument(
    "old", required=True, help="Current credential cannot be blank!"
)
credentials_change_put.add_argument(
    "new", required=True, help="New credential cannot be blank!"
)


@api.route("/account_credentials")
class CredentialsChange(Resource):
    @api.expect(credentials_change_put)
    @jwt_required()
    def put(self):
        """Endpoint to change user credentials email or password."""

        args = credentials_change_put.parse_args()
        credential_type = args.get("credential_type")
        old_credential = args.get("old")
        new_credential = args.get("new")

        token_payload = get_jwt()
        user_id = token_payload.get("sub")
        user = User.query.filter_by(id=user_id).first_or_404()
        is_credential_changed, error = auth_service.change_user_credentials(
            user,
            credential_type,
            old_credential,
            new_credential,
        )
        if not is_credential_changed:
            return abort(HTTPStatus.BAD_REQUEST, error)
        return {"msg": "Credentials changed successfully."}


logout_post_parser = reqparse.RequestParser()
logout_post_parser.add_argument("User-Agent", location="headers")
logout_post_parser.add_argument(
    "is_full", required=False, type=bool, help="Logout from all accounts!"
)


@api.route("/logout")
class Logout(Resource):
    """Endpoint to user logout."""

    @api.expect(logout_post_parser)
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

    @api.expect(register_post_parser)
    def post(self):
        """Register a new user."""
        args = register_post_parser.parse_args()
        email = args.get("email")
        password = args.get("password")

        if USER_DATASTORE.get_user(identifier=email):
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

    @api.expect(refresh_post_parser)
    @jwt_required(refresh=True)
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
