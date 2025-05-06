from enum import StrEnum, auto

OIDC_STATES_SESSION_KEY = "_hidp_oidc_states"


class OIDCError(StrEnum):
    ACCOUNT_EXISTS = auto()
    REQUEST_EXPIRED = auto()
    UNEXPECTED_ERROR = auto()
    INVALID_TOKEN = auto()
    INVALID_CREDENTIALS = auto()
    REGISTRATION_DISABLED = auto()
