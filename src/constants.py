import operator
import string
from enum import Enum


class CredentialType(Enum):
    """Credential types representation."""

    PASSWORD = "password"
    EMAIL = "email"


class Const(Enum):
    ALPHABET = string.ascii_letters + string.digits


class MathOperator(Enum):
    ADD = operator.add
    SUB = operator.sub


operators_mapping = {"+": operator.add, "-": operator.sub, "*": operator.mul}
