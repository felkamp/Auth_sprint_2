from flask import Flask, request
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
from src.utils.jaeger import jaeger_tracer

from .config import Settings

login_manager = LoginManager()


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

    JWTManager(app)
    Security(app, SQLAlchemyUserDatastore(db, User, Role), register_blueprint=False)

    app.register_blueprint(account)
    app.register_blueprint(admin)

    return app


app = create_app()

jaeger_tracer.close()
