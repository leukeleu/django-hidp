import hashlib

from datetime import timedelta

from django.core import signing


class BaseEmailVerificationTokenGenerator:
    key_salt = NotImplemented
    token_timeout = NotImplemented

    def _get_signer(self):
        return signing.TimestampSigner(algorithm="sha256", salt=self.key_salt)

    def make_token(self, user):
        """
        Generate a token based on the user's email address.

        Args:
            user (User): The user to generate the token for.

        Returns:
            str: The generated token.
        """
        # Create a base64 encoded MD5 hash of the user's email address.
        # MD5 is used here to create a fixed length hash that is not reversible,
        # and can be used for easy and cheap database lookups.
        # The hash is then signed to prevent tampering.
        value = signing.b64_encode(
            hashlib.md5(
                user.email.encode(),
                usedforsecurity=False,
            )
            .hexdigest()
            .encode()
        ).decode()
        return self._get_signer().sign(value)

    def check_token(self, token):
        """
        Verify the token and return the hash of the email address used to generate it.

        Returns None if the token is invalid or expired.
        """
        try:
            return signing.b64_decode(
                self._get_signer().unsign(token, max_age=self.token_timeout).encode()
            ).decode()
        except signing.BadSignature:
            return None


class EmailVerificationRequestTokenGenerator(BaseEmailVerificationTokenGenerator):
    """Token to request a new email verification link."""

    key_salt = "email-verification-request"
    token_timeout = timedelta(hours=1).total_seconds()


email_verification_request_token_generator = EmailVerificationRequestTokenGenerator()
