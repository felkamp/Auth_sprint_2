from src.config import Settings


def api_url_wth_path(path: str) -> str:
    """Return api url with specified path"""
    return f"{Settings.API_URL}{path}"
