import hashlib

from datetime import timedelta

from django.core import signing


class EmailVerificationRequestTokenGenerator:
    key_salt = "hidp.accounts.tokens.EmailVerificationRequestTokenGenerator"

    def _get_signer(self):
        return signing.Signer(algorithm="sha256", salt=self.key_salt)

    def make_token(self, user):
        """
        Generate a token that can be used to request a new verification email.

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
        try:
            return signing.b64_decode(
                self._get_signer().unsign(token).encode()
            ).decode()
        except signing.BadSignature:
            return None


email_verification_request_token_generator = EmailVerificationRequestTokenGenerator()


class EmailVerificationTokenGenerator:
    key_salt = "hidp.accounts.tokens.VerifyEmailTokenGenerator"
    token_timeout = timedelta(days=1).total_seconds()

    def make_token(self, user):
        return signing.dumps(
            {"email": user.email},
            salt=self.key_salt,
        )

    def check_token(self, user, token):
        if not (user and token):
            return False

        try:
            data = signing.loads(token, salt=self.key_salt, max_age=self.token_timeout)
        except signing.BadSignature:
            # Token is invalid
            return False

        if data.get("email") != user.email:
            # Email in the token doesn't match the user's email
            return False

        if user.email_verified or not user.is_active:  # noqa: SIM103 (do not simplify)
            # The user's email address is already verified or the user is
            # deactivated, so the token is invalid.
            return False

        return True


email_verification_token_generator = EmailVerificationTokenGenerator()
