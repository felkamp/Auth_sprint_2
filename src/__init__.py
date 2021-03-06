from authlib.integrations.flask_client import OAuth
from flask import Blueprint, Flask, request
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_restx import Api
from flask_security import Security, SQLAlchemyUserDatastore

from src.account.views import account, api as account_api
from src.admin.views import admin, api as admin_api
from src.auth.views import auth, api as auth_api
from src.oauth.views import oauth, api as oauth_api
from src.security.views import security, api as security_api
from src.db.postgres import db, init_db
from src.db.redis import init_redis_db
from src.models.user import Role, User
from src.services import oauth as oauth_service
from src.utils.jaeger import jaeger_tracer

from .config import OAuthSettings, Settings

login_manager = LoginManager()
oauth_client = OAuth()


def create_app(config=None):
    app = Flask(__name__)

    if Settings.TRACE_ON:

        @app.before_request
        def before_request():
            request_id = request.headers.get("X-Request-Id")
            if not request_id:
                raise RuntimeError("request id is requred")

    login_manager.login_view = "account.login"
    login_manager.init_app(app)
    app.config.from_object(Settings)

    init_db(app)
    init_redis_db(app)

    oauth_client.init_app(app)
    oauth_service.google = oauth_service.register_google(oauth_client)

    JWTManager(app)
    Security(app, SQLAlchemyUserDatastore(db, User, Role), register_blueprint=False)

    blueprint = Blueprint("api", __name__)
    api = Api(
        blueprint,
        title=Settings.APP_NAME,
        description=Settings.APP_DESCRIPTION,
        doc=Settings.API_DOC_PREFIX,
        validate=Settings.RESTX_VALIDATE,
    )

    app.register_blueprint(blueprint=blueprint, url_prefix="/")
    app.register_blueprint(blueprint=account)
    app.register_blueprint(blueprint=admin)
    app.register_blueprint(blueprint=auth)
    app.register_blueprint(blueprint=oauth)
    app.register_blueprint(blueprint=security)

    api.add_namespace(account_api)
    api.add_namespace(admin_api)
    api.add_namespace(auth_api)
    api.add_namespace(oauth_api)
    api.add_namespace(security_api)

    return app


app = create_app()

jaeger_tracer.close()
