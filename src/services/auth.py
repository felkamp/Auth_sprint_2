import time
import json
from typing import Optional

from flask_jwt_extended import (create_access_token, create_refresh_token,
                                decode_token)
from flask_security.utils import hash_password, verify_password
from loguru import logger
from marshmallow import Schema, fields
from rauth import OAuth2Service

from src.constants import CredentialType
from src.db.postgres import db
from src.db.redis import redis_db
from src.models.user import (
    USER_DATASTORE, AuthorizationUserLog,
    User, SocialAccount,
)
from src.config import Settings


GOOGLE_AUTH_SERVICE = OAuth2Service(
    name='google',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_id=Settings.GOOGLE_CLIENT_ID,
    client_secret=Settings.GOOGLE_CLIENT_SECRET,
    base_url='https://accounts.google.com/o/oauth2/auth'
)


class AuthUserLogSchema(Schema):
    """Schema to represent AuthorizationUserLog model."""

    id = fields.UUID()
    device = fields.Str()
    logged_at = fields.DateTime(attribute="created_at")


class AuthService:
    """Auth service for users."""

    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """Check user credentials - login and password.

        If credentials is correct return user object.
        """
        user = USER_DATASTORE.get_user(identifier=email)
        if not user:
            return None
        password_is_correct = verify_password(password, user.password)
        if not password_is_correct:
            return None
        return user

    def authenticate_user_with_google(
            self, code: str, redirect_uri: str):
        """Check authentication with google user account.

        If authentication is correct, return user object.
        """
        try:
            oauth2_session = GOOGLE_AUTH_SERVICE.get_auth_session(
                data={
                    'code': code,
                    'grant_type': 'authorization_code',
                    'redirect_uri': redirect_uri,
                },
                decoder=json.loads
            )
        except Exception as error:
            logger.error(
                f'When logging in through Google, '
                f'the following error occurred - {error}')
            return None

        user_info = oauth2_session.get(
            'https://www.googleapis.com/oauth2/v1/userinfo').json()
        email = user_info.get('email')
        social_id = user_info.get('id')
        social_name = 'google'

        social_accoint, _ = SocialAccount.get_or_create(
            social_id, social_name, email
        )
        user = social_accoint.user

        return user

    def redis_key(self, user_id: str, user_agent: str) -> str:
        """Key template for redis db."""
        return f"{user_id}:{user_agent}"

    def save_refresh_token_in_redis(self, token: str, user_agent: str):
        """Save refresh token in Redis db."""
        token_payload = decode_token(token)
        user_id = token_payload.get("sub")
        expired = token_payload.get("exp")
        expired_seconds_time = int(expired - time.time())
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        redis_db.setex(name=redis_key, time=expired_seconds_time, value=token)

    def delete_all_refresh_tokens(self, user_id: str):
        """Delete all refresh user tokens from redis db."""
        keys = redis_db.keys(f"*{user_id}*")
        if keys:
            redis_db.delete(*keys)

    def delete_user_refresh_token(self, user_id: str, user_agent: str):
        """Delete user refresh token from Redis db."""
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        redis_db.delete(redis_key)

    def get_jwt_tokens(self, user: User) -> dict:
        """Get access and refresh tokens for authenticate user."""
        permissions = 0
        for role in user.roles:
            permissions |= role.permissions
        permissions = {"perms": permissions}

        access_token = create_access_token(
            identity=user.id, additional_claims=permissions
        )
        refresh_token = create_refresh_token(identity=user.id)
        return {
            "access": access_token,
            "refresh": refresh_token,
        }

    def create_user_auth_log(self, user_id: str, device: str):
        """Create AuthorizationUserLog record after successful user auth."""
        try:
            auth_log = AuthorizationUserLog(user_id=user_id, device=device)
            db.session.add(auth_log)
            db.session.commit()
        except Exception as error:
            logger.error(
                f"When saving the user authorization log,"
                f" the following error occurred - {error}"
            )

    def get_auth_user_logs(self, user_id: str):
        """Get user login history information."""
        user_auth_logs = AuthorizationUserLog.query.filter_by(user_id=user_id)
        auth_user_log_schema = AuthUserLogSchema(
            many=True, only=("device", "logged_at")
        )
        return auth_user_log_schema.dump(user_auth_logs)

    def refresh_jwt_tokens(self, user_id: str, user_agent: str) -> Optional[dict]:
        """Get user refresh token from Redis db."""
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        token_in_redis: Optional[bytes] = redis_db.get(redis_key)
        if token_in_redis:
            self.delete_user_refresh_token(user_id=user_id, user_agent=user_agent)
            user = User.query.filter_by(id=user_id).first_or_404()
            jwt_tokens: Optional[dict] = self.get_jwt_tokens(user=user)
            return jwt_tokens

    def _change_password(
        self, user: User, old_password: str, new_password: str
    ) -> tuple:
        """Change password for user.

        If it was failed to change the password,
        return False and an error message.
        """
        is_correct_password = verify_password(old_password, user.password)
        if not is_correct_password:
            return False, "Incorrect user password."
        if len(new_password) < 8:
            return False, "Incorrect new password length. Must be more then 7."

        user.password = hash_password(new_password)
        db.session.commit()
        return True, ""

    def _change_email(self, user, new_email) -> tuple:
        """Change login for user.

        If it was failed to change the email,
        return False and an error message.
        """
        user_with_new_email = User.query.filter_by(email=new_email).first()
        if user_with_new_email:
            return False, "User with new email already exists."
        user.email = new_email
        db.session.commit()
        return True, ""

    def change_user_credentials(
        self, user, credential_type: str, old_credential, new_credential
    ):
        """Change credentials for user - password or email."""
        if credential_type == CredentialType.EMAIL.value:
            return self._change_email(user, new_credential)
        if credential_type == CredentialType.PASSWORD.value:
            return self._change_password(user, old_credential, new_credential)


auth_service = AuthService()
