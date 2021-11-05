from authlib.integrations.flask_client import OAuth
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_security import Security, SQLAlchemyUserDatastore

from src.account.views import account
from src.account.views import api as auth_api
from src.admin.views import admin
from src.admin.views import api as admin_api
from src.db.postgres import db, init_db
from src.db.redis import init_redis_db
from src.models.user import Role, User
from src.services import oauth

from .config import Settings, OAuthSettings

login_manager = LoginManager()
oauth_client = OAuth()


def create_app(config=None):
    app = Flask(__name__)

    login_manager.login_view = "account.login"
    login_manager.init_app(app)
    app.config.from_object(Settings)

    init_db(app)
    init_redis_db(app)

    oauth_client.init_app(app)
    oauth.google = oauth.register_google(oauth_client)

    JWTManager(app)
    Security(app, SQLAlchemyUserDatastore(db, User, Role), register_blueprint=False)

    app.register_blueprint(account, url_prefix='/account')
    app.register_blueprint(admin, url_prefix='/admin')

    return app


app = create_app()
