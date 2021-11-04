from flask import Blueprint, Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_restx import Api
from flask_security import Security, SQLAlchemyUserDatastore

from src.account.views import account
from src.account.views import api as auth_api
from src.admin.views import admin
from src.admin.views import api as admin_api
from src.db.postgres import db, init_db
from src.db.redis import init_redis_db
from src.models.user import Role, User

from .config import Settings

login_manager = LoginManager()


def create_app(config=None):
    app = Flask(__name__)

    login_manager.login_view = "account.login"
    login_manager.init_app(app)
    app.config.from_object(Settings)

    init_db(app)
    init_redis_db(app)

    JWTManager(app)
    Security(app, SQLAlchemyUserDatastore(
        db, User, Role), register_blueprint=False)

    blueprint = Blueprint("api", __name__)
    api = Api(
        blueprint,
        title=Settings.APP_NAME,
        description=Settings.APP_DESCRIPTION,
        doc=Settings.API_DOC_PREFIX,
        validate=Settings.RESTX_VALIDATE,
    )

    app.register_blueprint(blueprint=blueprint)
    app.register_blueprint(blueprint=account)
    app.register_blueprint(blueprint=admin)

    api.add_namespace(auth_api)
    api.add_namespace(admin_api)

    return app


app = create_app()
