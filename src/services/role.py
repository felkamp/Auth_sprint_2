from typing import Optional

from sqlalchemy import func

from src.db.postgres import db
from src.models.user import Role


class RoleService:
    def add_role(
        self, role_name: str, permissions: int, description: Optional[str]
    ) -> None:
        role = Role(name=role_name, permissions=permissions, description=description)
        db.session.add(role)
        db.session.commit()

    def get_role_by_id(self, id: str):
        return Role.query.filter_by(id=id).first()

    def get_role_by_name(self, name: str):
        return Role.query.filter(func.lower(Role.name) == func.lower(name)).first()

    def get_roles(self, page: int, size: int) -> list:
        res = Role.query.paginate(page, size, False)
        return res.items

    def update_role(self, role: Role, updated_fields: dict):
        for key, value in updated_fields.items():
            setattr(role, key, value)

        db.session.add(role)
        db.session.commit()

    def delete_role(self, id: str):
        Role.query.filter_by(id=id).delete()
        db.session.commit()


role_service = RoleService()
