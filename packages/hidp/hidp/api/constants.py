from enum import StrEnum


class Step(StrEnum):
    """Steps a client must complete before the user is fully authenticated."""

    EMAIL_VERIFY = "email_verify"
