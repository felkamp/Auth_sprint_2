import uuid
from datetime import datetime

from flask_security import RoleMixin, SQLAlchemyUserDatastore, UserMixin
from sqlalchemy.dialects.postgresql import UUID

from src.db.postgres import db

from .mixins import AuditMixin

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", UUID(as_uuid=True), db.ForeignKey("users.id")),
    db.Column("role_id", UUID(as_uuid=True), db.ForeignKey("roles.id")),
    db.Column("created_at", db.DateTime(timezone=True), default=datetime.now),
    db.Column(
        "update_at",
        db.DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
    ),
)


class Permission:
    VIEW = 4
    CREATE = 8
    UPDATE = 16
    DELETE = 32
    ADMIN = 255


class User(db.Model, AuditMixin, UserMixin):
    """Model to represent User data."""

    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean())
    roles = db.relationship(
        "Role",
        secondary=roles_users,
        backref=db.backref("users", lazy="dynamic"),
    )
    auth_logs = db.relationship("AuthorizationUserLog", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.email}>"


class Role(db.Model, AuditMixin, RoleMixin):
    """Model to represent Role data related with users."""

    __tablename__ = "roles"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(80), unique=True, nullable=False)
    permissions = db.Column(db.Integer)
    description = db.Column(db.String(255), nullable=True)


class AuthorizationUserLog(db.Model, AuditMixin):
    """Model to represent log about successful user authorization."""

    __tablename__ = "auth_user_logs"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id"),
        nullable=False,
    )
    device = db.Column(db.String(255), nullable=True)


USER_DATASTORE = SQLAlchemyUserDatastore(db, User, Role)
