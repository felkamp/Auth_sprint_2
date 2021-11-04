import uuid
from datetime import datetime

from flask_security import RoleMixin, SQLAlchemyUserDatastore, UserMixin
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import UniqueConstraint, ForeignKeyConstraint

from src.db.postgres import db

from .mixins import AuditMixin

roles_users = db.Table(
    "roles_users",
    db.Column("user_id"),
    db.Column("user_date_of_birth"),
    db.Column("role_id", UUID(as_uuid=True), db.ForeignKey("roles.id")),
    db.Column("created_at", db.DateTime(timezone=True), default=datetime.now),
    db.Column(
        "update_at",
        db.DateTime(timezone=True),
        default=datetime.now,
        onupdate=datetime.now,
    ),
    db.ForeignKeyConstraint(
        ['user_id', 'user_date_of_birth'],
        ["users.id", "users.date_of_birth"], name='fk_user_id_birth'
    )
)


class Permission:
    VIEW = 4
    CREATE = 8
    UPDATE = 16
    DELETE = 32
    ADMIN = 255


def create_partition_for_users(target, connection, **kw) -> None:
    """Create users partition by date of birth."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS "users_birthdays_1900_to_1950"
        PARTITION OF "users"
        FOR VALUES FROM ('1900-12-31') TO ('1950-12-31');
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS "users_birthdays_1950_to_2000"
        PARTITION OF "users"
        FOR VALUES FROM ('1950-12-31') TO ('2000-12-31');
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS "users_birthdays_2000_to_2050"
        PARTITION OF "users"
        FOR VALUES FROM ('2000-12-31') TO ('2050-12-31');
        """
    )


class User(db.Model, AuditMixin, UserMixin):
    """Model to represent User data."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint('id', 'email', 'date_of_birth'),
        {
            'postgresql_partition_by': 'RANGE (date_of_birth)',
            'listeners': [('after_create', create_partition_for_users)],
        }
    )

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean())
    date_of_birth = db.Column(
        db.Date, primary_key=True,
        default=datetime.today().date()
    )
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
    __table_args__ = (
        ForeignKeyConstraint(
            ['user_id', 'user_date_of_birth'],
            ["users.id", "users.date_of_birth"],
            name='fk_user_id_birth'
        ),
    )
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), nullable=False)
    user_date_of_birth = db.Column(db.Date, nullable=False)
    device = db.Column(db.String(255), nullable=True)


USER_DATASTORE = SQLAlchemyUserDatastore(db, User, Role)
