from enum import StrEnum


class Step(StrEnum):
    """Steps a client must complete before the user is fully authenticated."""

    EMAIL_VERIFY = "email_verify"
    OTP_VERIFY = "otp_verify"
    OTP_SETUP = "otp_setup"
