from http import HTTPStatus

from flask import Blueprint, abort
from flask_jwt_extended import get_jwt, jwt_required
from flask_restx import Namespace, Resource, reqparse
from opentracing_decorator import Tracing

from src.models.user import SocialAccount, User
from src.services.auth import auth_service
from src.services.user import user_service
from src.utils.jaeger import jaeger_tracer
from src.utils.rate_limit import rate_limit

account = Blueprint("account", __name__)
api = Namespace(name="account", description=" API for account management")
tracing = Tracing(tracer=jaeger_tracer)


@api.route("/login_history")
class LoginHistory(Resource):
    """Endpoint to represent user login history."""

    @tracing.trace(operation_name="History")
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

    @tracing.trace(operation_name="Credentials")
    @rate_limit()
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


@api.route("/social_accounts/<string:social_account_id>")
class UserSocialAccounts(Resource):
    @rate_limit()
    @jwt_required()
    def delete(self, social_account_id):
        """Delete user social account."""

        token_payload = get_jwt()
        user_id = token_payload.get("sub")

        SocialAccount.query.filter_by(id=social_account_id, user_id=user_id).first_or_404()
        user_service.delete_socail_account(user_id=user_id, social_account_id=social_account_id)

        return {"msg": "Social account deleted."}
