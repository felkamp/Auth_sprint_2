from src.db.postgres import db
from src.models.user import Role, User, roles_users


class UserService:
    def add_role(self, user: User, role: Role) -> None:
        user.roles.append(role)
        db.session.commit()

    def has_role(self, user_id: str, role_id: str) -> bool:
        res = (
            db.session.query(roles_users)
            .filter_by(user_id=user_id, role_id=role_id)
            .first()
        )
        return bool(res)

    def delete_role(self, user: User, role: Role) -> None:
        user.roles.remove(role)
        db.session.commit()


user_service = UserService()
