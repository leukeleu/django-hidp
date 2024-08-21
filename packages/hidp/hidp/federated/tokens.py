import uuid

from datetime import timedelta

from django.core import signing


class BaseTokenGenerator:
    key_salt = NotImplemented
    token_timeout = NotImplemented

    def _get_signer(self):
        return signing.TimestampSigner(algorithm="sha256", salt=self.key_salt)

    def make_token(self):
        """
        Generate an expiring token based on a random value.

        Returns:
            str: The generated token.
        """
        value = str(uuid.uuid4())
        return self._get_signer().sign(value)

    def check_token(self, token):
        """
        Verify the token.

        Returns:
            bool: True if the token is valid, False otherwise.
        """
        try:
            self._get_signer().unsign(token, max_age=self.token_timeout)
        except signing.BadSignature:
            return False
        return True


class OIDCRegistrationTokenGenerator(BaseTokenGenerator):
    """Token for the OIDC registration process."""

    key_salt = "oidc-registration"
    token_timeout = timedelta(minutes=15).total_seconds()


class OIDCLoginTokenGenerator(BaseTokenGenerator):
    """Token for the OIDC login process."""

    key_salt = "oidc-login"
    token_timeout = timedelta(minutes=5).total_seconds()


class OIDCAccountLinkTokenGenerator(BaseTokenGenerator):
    """Token for the OIDC account linking process."""

    key_salt = "oidc-account-link"
    token_timeout = timedelta(minutes=15).total_seconds()
