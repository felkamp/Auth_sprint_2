import uuid

from datetime import datetime
from random import choice

from flask_security.registerable import register_user
from flask_security import RoleMixin, SQLAlchemyUserDatastore, UserMixin
from flask_security.utils import hash_password
from sqlalchemy.dialects.postgresql import UUID

from src.db.postgres import db
from src.constants import Const
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


class SocialAccountName:
    GOOGLE = 'google'


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

    @staticmethod
    def generate_password(size=8, chars=Const.ALPHABET.value):
        return ''.join(choice(chars) for _ in range(size))


class SocialAccount(db.Model):
    """Model to represent User social account."""
    __tablename__ = 'social_accounts'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey('users.id'),
        nullable=False,
    )
    user = db.relationship(
        User, backref=db.backref('social_accounts', lazy=True),
    )
    social_id = db.Column(db.Text, nullable=False)
    social_name = db.Column(db.Text, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('social_id', 'social_name', name='social_pk'),
    )

    def __repr__(self):
        return f'<SocialAccount {self.social_name}:{self.user_id}>'

    @staticmethod
    def get_or_create(social_id: str, social_name: str, email: str):
        """Get or create social account instance."""

        social_account = SocialAccount.query.filter_by(
            social_id=social_id, social_name=social_name,
        ).first()
        if social_account is not None:
            return social_account

        user = register_user(
            email=email,
            password=hash_password(User.generate_password())
        )
        social_account = SocialAccount(
            social_id=social_id, social_name=social_name, user_id=user.id
        )
        db.session.add(social_account)
        db.session.commit()

        return social_account


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
