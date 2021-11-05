from src.config import OAuthSettings

google = None


def register_google(oauth_client):
    return oauth_client.register(
        name="google",
        client_id=OAuthSettings.GOOGLE_CLIENT_ID,
        client_secret=OAuthSettings.GOOGLE_CLIENT_SECRET,
        access_token_url=OAuthSettings.GOOGLE_ACCESS_TOKEN_URL,
        authorize_url=OAuthSettings.GOOGLE_AUTHORIZE_URL,
        api_base_url=OAuthSettings.GOOGLE_API_BASE_URL,
        client_kwargs={"scope": "openid profile email"},
    )


def get_google_oauth_client():
    return google
