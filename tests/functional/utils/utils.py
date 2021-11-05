from src.config import Settings


def account_url_path(path: str) -> str:
    """Return account api url with specified path"""
    return f"{Settings.API_URL}/account{path}"


def admin_url_path(path: str) -> str:
    """Return admin api url with specified path"""
    return f"{Settings.API_URL}/admin{path}"
