import uuid

from datetime import timedelta

from ..accounts.tokens import BaseTokenGenerator


class BaseOIDCTokenGenerator(BaseTokenGenerator):
    def make_token(self):
        """
        Generate an expiring token based on a random value.

        Returns:
            str: The generated token.
        """
        return super().make_token(str(uuid.uuid4()))

    def check_token(self, token):
        """
        Verify a token.

        Args:
            token (str): The token to verify.

        Returns:
            bool: True if the token is valid, False otherwise.
        """
        return super().check_token(token) is not None


class OIDCRegistrationTokenGenerator(BaseOIDCTokenGenerator):
    """Token for the OIDC registration process."""

    key_salt = "oidc-registration"
    token_timeout = timedelta(minutes=15).total_seconds()


class OIDCLoginTokenGenerator(BaseOIDCTokenGenerator):
    """Token for the OIDC login process."""

    key_salt = "oidc-login"
    token_timeout = timedelta(minutes=5).total_seconds()


class OIDCAccountLinkTokenGenerator(BaseOIDCTokenGenerator):
    """Token for the OIDC account linking process."""

    key_salt = "oidc-account-link"
    token_timeout = timedelta(minutes=15).total_seconds()
