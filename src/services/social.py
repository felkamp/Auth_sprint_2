from src.models.user import SocialAccount
from src.models.user import SocialAccountName


class SocialService:

    def get_social_account(self, data: dict) -> SocialAccount:
        return SocialAccount.get_or_create(
            social_id=data.get("id"),
            social_name=SocialAccountName.GOOGLE,
            email=data.get("email"),
        )


social_service = SocialService()
