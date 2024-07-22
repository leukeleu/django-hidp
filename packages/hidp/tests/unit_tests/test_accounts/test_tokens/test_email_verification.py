import base64
import hashlib

from django.test import TestCase

from hidp.accounts.tokens import email_verification_request_token_generator
from hidp.test.factories import user_factories


class TestEmailVerificationRequestTokenGenerator(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.token = email_verification_request_token_generator.make_token(cls.user)

    def test_make_token(self):
        """
        The token is a signed base64 encoded MD5 sum of the user's email address.
        """
        value, _sep, _signature = self.token.partition(":")
        self.assertEqual(
            value,
            base64.urlsafe_b64encode(
                hashlib.md5(
                    self.user.email.encode(),
                    usedforsecurity=False,
                )
                .hexdigest()
                .encode()
            )
            .decode()
            .rstrip("="),
        )

    def test_check_invalid_token(self):
        """
        An invalid token returns none
        """
        self.assertIsNone(
            email_verification_request_token_generator.check_token(
                "garbage-in:garbage-out"
            )
        )

    def test_check_valid_token(self):
        """
        A valid token returns the MD5 sum of the email address.
        """
        self.assertEqual(
            email_verification_request_token_generator.check_token(self.token),
            hashlib.md5(
                self.user.email.encode(),
                usedforsecurity=False,
            ).hexdigest(),
        )
