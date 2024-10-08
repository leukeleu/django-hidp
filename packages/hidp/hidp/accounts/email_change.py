from enum import StrEnum, auto


class Recipient(StrEnum):
    CURRENT_EMAIL = auto()
    PROPOSED_EMAIL = auto()
