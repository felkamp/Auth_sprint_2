import uuid

from http import HTTPStatus
from typing import Optional

from flask import Blueprint, abort
from flask_jwt_extended import get_jwt, jwt_required
from flask_restx import Resource, reqparse, fields, Namespace
from flask_security.registerable import register_user
from flask import url_for, redirect

from src.db.redis import redis_db
from src.models.user import USER_DATASTORE, User, SocialAccount, SocialAccountName
from src.services.auth import auth_service
from src.services.user import user_service
from src.services.oauth import get_google_oauth_client
from src.utils.utils import get_simple_math_problem
from src.utils.rate_limit import rate_limit

account = Blueprint("account", __name__)

api = Namespace(
    name="account", description="Account API for Authentication service")

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
login_post_parser.add_argument(
    "email", required=True, help="Email cannot be blank!")
login_post_parser.add_argument(
    "password", required=True, help="Password cannot be blank!"
)
login_post_parser.add_argument("User-Agent", location="headers")


@api.route("/login")
class Login(Resource):
    """Endpoint to user login."""

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
        jwt_tokens = auth_service.get_jwt_tokens(authenticated_user)

        user_agent = args.get("User-Agent")
        auth_service.save_refresh_token_in_redis(
            jwt_tokens.get("refresh"), user_agent)
        auth_service.create_user_auth_log(
            user_id=authenticated_user.id,
            device=user_agent,
            user_date_of_birth=authenticated_user.date_of_birth,
        )

        return jwt_tokens


@api.route("/login_history")
class LoginHistory(Resource):
    """Endpoint to represent user login history."""

    @rate_limit()
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
    """Endpoint to change account credentials."""

    @rate_limit()
    @api.expect(credentials_change_put)
    @jwt_required()
    @api.marshal_with(msg_response_model, code=HTTPStatus.OK)
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


@api.route("/social_accounts/<string:id>")
class UserSocialAccounts(Resource):

    @rate_limit()
    @jwt_required()
    def delete(self, id):
        """Delete user social account."""

        token_payload = get_jwt()
        user_id = token_payload.get("sub")

        SocialAccount.query.filter_by(id=id, user_id=user_id).first_or_404()
        user_service.delete_socail_account(id=id)

        return {"msg": "Social account deleted."}


logout_post_parser = reqparse.RequestParser()
logout_post_parser.add_argument("User-Agent", location="headers")
logout_post_parser.add_argument(
    "is_full", required=False, type=bool, help="Logout from all accounts!"
)


@api.route("/logout")
class Logout(Resource):
    """Endpoint to user logout."""

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
register_post_parser.add_argument(
    "email", required=True, help="Email cannot be blank!")
register_post_parser.add_argument(
    "password", required=True, help="Password cannot be blank!"
)


@api.route("/register")
class Register(Resource):
    """Endpoint to sign up."""

    @rate_limit()
    @api.expect(register_post_parser)
    @api.marshal_with(msg_response_model, code=HTTPStatus.OK)
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


@api.route("/google_login")
class GoogleLogin(Resource):

    @rate_limit()
    def get(self):
        """Authenticate using google."""

        google = get_google_oauth_client()
        redirect_uri = url_for('api.account_google_authorize', _external=True)
        return google.authorize_redirect(redirect_uri)


google_authorize_parser = reqparse.RequestParser()
google_authorize_parser.add_argument("User-Agent", location="headers")


@api.route("/google_authorize")
class GoogleAuthorize(Resource):

    @rate_limit()
    def get(self):
        """Google authorization processing."""

        args = google_authorize_parser.parse_args()
        google = get_google_oauth_client()
        resp = google.get('userinfo', token=google.authorize_access_token())
        resp.raise_for_status()

        profile_data = resp.json()
        if 'id' not in profile_data or 'email' not in profile_data:
            abort(HTTPStatus.BAD_REQUEST)
        if User.query.filter_by(email=profile_data.get('email')).first():
            return redirect(url_for('api.account_login', _external=False))

        social_account = SocialAccount.get_or_create(
            social_id=profile_data.get('id'),
            social_name=SocialAccountName.GOOGLE,
            email=profile_data.get('email')
        )
        if not social_account:
            return abort(HTTPStatus.FORBIDDEN)

        authenticated_user = User.query.filter_by(id=social_account.user_id).first()
        jwt_tokens = auth_service.get_jwt_tokens(authenticated_user)
        user_agent = args.get("User-Agent")
        auth_service.save_refresh_token_in_redis(jwt_tokens.get("refresh"), user_agent)
        auth_service.create_user_auth_log(
            user_id=authenticated_user.id, device=user_agent,
            user_date_of_birth=authenticated_user.date_of_birth
        )

        return jwt_tokens


@api.route("/captcha")
class Captcha(Resource):

    @rate_limit()
    def get(self):
        """Get simple math problem."""
        problem_id = str(uuid.uuid4())
        problem, answer = get_simple_math_problem()
        redis_db.setex(name=problem_id, time=60 * 5, value=answer)
        return {'id': problem_id, 'math_problem': problem}


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

        if not (real_answer := redis_db.get(problem_id)):
            abort(HTTPStatus.NOT_FOUND)

        msg = 'ok' if str(user_answer) == str(real_answer.decode("utf-8")) else 'error'
        redis_db.delete(problem_id)

        return {'msg': msg}
