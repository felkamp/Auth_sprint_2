from http import HTTPStatus

from flask import Blueprint, abort, redirect, url_for
from flask_restx import Namespace, Resource, fields, reqparse

from src.models.user import User
from src.services.auth import auth_service
from src.services.oauth import get_google_oauth_client
from src.services.social import social_service
from src.utils.rate_limit import rate_limit

oauth = Blueprint("oauth", __name__)

api = Namespace(name="oauth", description="API for oauth service")

tokens_response_model = api.model(
    "Token data response",
    {
        "access": fields.String(default="JWTTOKENACCESS"),
        "refresh": fields.String(default="JWTTOKENREFRESH"),
    },
)


@api.route("/google_login")
class GoogleLogin(Resource):
    @rate_limit()
    def get(self):
        """Authenticate using google."""

        google = get_google_oauth_client()
        redirect_uri = url_for("api.oauth_google_authorize", _external=True)
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
        resp = google.get("userinfo", token=google.authorize_access_token())
        resp.raise_for_status()

        profile_data = resp.json()
        if "id" not in profile_data or "email" not in profile_data:
            abort(HTTPStatus.BAD_REQUEST)
        if User.query.filter_by(email=profile_data.get("email")).first():
            return redirect(url_for("api.auth_login", _external=False))

        if not (social_account := social_service.get_social_account(profile_data)):
            return abort(HTTPStatus.FORBIDDEN)

        authenticated_user = User.query.filter_by(id=social_account.user_id).first()
        return auth_service.get_user_tokens(authenticated_user, args.get("User-Agent"))
