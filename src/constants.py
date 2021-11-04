import string

from enum import Enum


class CredentialType(Enum):
    """Credential types representation."""

    PASSWORD = "password"
    EMAIL = "email"


class Const(Enum):
    ALPHABET = string.ascii_letters + string.digits
