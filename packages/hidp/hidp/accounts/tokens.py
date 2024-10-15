import hashlib

from datetime import timedelta

from django.core import signing

from .email_change import Recipient


class BaseTokenGenerator:
    key_salt = NotImplemented
    token_timeout = NotImplemented

    def __init__(self):
        self._signer = self._get_signer()

    def _get_signer(self):
        return signing.TimestampSigner(algorithm="sha256", salt=self.key_salt)

    def make_token(self, value):
        """
        Generate an expiring token based on a value.

        Args:
            value:
                The value to use to generate the token.

        Returns:
            str: The generated token.
        """
        if value is None:
            # The value should not be `None` because it would be impossible to verify as
            # `None` is returned when the token is invalid or expired.
            raise ValueError("The value cannot be None.")
        return self._signer.sign_object(value)

    def check_token(self, token):
        """
        Verify a token.

        Args:
            token (str): The token to verify.

        Returns:
            value | None:
                The value used to generate the token,
                or `None` if the token is invalid or expired.
        """
        try:
            return self._signer.unsign_object(token, max_age=self.token_timeout)
        except signing.BadSignature:
            return None


class BaseEmailVerificationTokenGenerator(BaseTokenGenerator):
    def make_token(self, user):
        """
        Generate an expiring token based on the user's email address.

        Args:
            user (User): The user to generate the token for.

        Returns:
            str: The generated token.
        """
        # Create a MD5 hash of the user's email address.
        # MD5 is used here to create a fixed length hash that is not reversible,
        # and can be used for easy and cheap database lookups.
        # The hash is then signed to prevent tampering.
        return super().make_token(
            hashlib.md5(
                user.email.encode(),
                usedforsecurity=False,
            ).hexdigest()
        )


class EmailVerificationRequestTokenGenerator(BaseEmailVerificationTokenGenerator):
    """Token to request a new email verification link."""

    key_salt = "email-verification-request"
    token_timeout = timedelta(hours=1).total_seconds()


email_verification_request_token_generator = EmailVerificationRequestTokenGenerator()


class EmailVerificationTokenGenerator(BaseEmailVerificationTokenGenerator):
    """Token to verify a user's email address."""

    key_salt = "email-verification"
    token_timeout = timedelta(days=1).total_seconds()


email_verification_token_generator = EmailVerificationTokenGenerator()


class EmailChangeTokenGenerator(BaseTokenGenerator):
    """Token to confirm an email change request."""

    key_salt = "email-change"
    token_timeout = timedelta(days=1).total_seconds()

    def make_token(self, email_change_request_uuid, recipient):
        """Generate a token based on the email change request and recipient."""
        if recipient not in Recipient.__members__.values():
            raise ValueError(f"Invalid recipient: {recipient}")

        return super().make_token(
            {
                "uuid": str(email_change_request_uuid),
                "recipient": recipient,
            }
        )


email_change_token_generator = EmailChangeTokenGenerator()
