import hashlib

from unittest import SkipTest

from django.test import TestCase

from hidp.accounts import tokens
from hidp.accounts.email_change import Recipient
from hidp.test.factories.user_factories import EmailChangeRequestFactory, UserFactory


class TestBaseEmailVerificationTokenGenerator(TestCase):
    token_generator = NotImplemented

    @classmethod
    def setUpClass(cls):
        if cls is TestBaseEmailVerificationTokenGenerator:
            raise SkipTest("Skipping abstract base class")
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserFactory()
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


class TestEmailChangeTokenGenerator(TestCase):
    token_generator = tokens.email_change_token_generator

    @classmethod
    def setUpTestData(cls):
        cls.user = UserFactory()
        cls.email_change_request = EmailChangeRequestFactory(user=cls.user)
        cls.current_token = cls.token_generator.make_token(
            str(cls.email_change_request.pk), Recipient.CURRENT_EMAIL
        )
        cls.proposed_token = cls.token_generator.make_token(
            str(cls.email_change_request.pk), Recipient.PROPOSED_EMAIL
        )

    def test_make_token_invalid_recipient(self):
        """An invalid recipient raises a ValueError."""
        with self.assertRaises(ValueError):
            self.token_generator.make_token(
                str(self.email_change_request.pk), "invalid-recipient"
            )

    def test_check_invalid_token(self):
        """An invalid token returns none."""
        self.assertIsNone(self.token_generator.check_token("garbage-in:garbage-out"))

    def test_check_valid_token(self):
        """A valid token returns the token object, containing uuid and recipient."""
        self.assertEqual(
            self.token_generator.check_token(self.current_token),
            {
                "uuid": str(self.email_change_request.pk),
                "recipient": Recipient.CURRENT_EMAIL,
            },
        )

        self.assertEqual(
            self.token_generator.check_token(self.proposed_token),
            {
                "uuid": str(self.email_change_request.pk),
                "recipient": Recipient.PROPOSED_EMAIL,
            },
        )
