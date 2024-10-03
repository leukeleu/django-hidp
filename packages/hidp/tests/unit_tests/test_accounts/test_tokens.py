import hashlib

from unittest import SkipTest

from django.test import TestCase

from hidp.accounts import tokens
from hidp.test.factories import user_factories


class TestBaseEmailVerificationTokenGenerator(TestCase):
    token_generator = NotImplemented

    @classmethod
    def setUpClass(cls):
        if cls is TestBaseEmailVerificationTokenGenerator:
            raise SkipTest("Skipping abstract base class")
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.token = cls.token_generator.make_token(cls.user)

    def test_check_invalid_token(self):
        """An invalid token returns none."""
        self.assertIsNone(self.token_generator.check_token("garbage-in:garbage-out"))

    def test_check_valid_token(self):
        """A valid token returns the MD5 sum of the email address."""
        self.assertEqual(
            self.token_generator.check_token(self.token),
            hashlib.md5(
                self.user.email.encode(),
                usedforsecurity=False,
            ).hexdigest(),
        )


class TestEmailVerificationRequestTokenGenerator(
    TestBaseEmailVerificationTokenGenerator
):
    token_generator = tokens.email_verification_request_token_generator


class TestEmailVerificationTokenGenerator(TestBaseEmailVerificationTokenGenerator):
    token_generator = tokens.email_verification_token_generator
