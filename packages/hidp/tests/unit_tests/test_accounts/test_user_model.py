import uuid

from django.core import mail
from django.db import IntegrityError
from django.test import TestCase, override_settings

from hidp.test.factories import user_factories


@override_settings(DEFAULT_FROM_EMAIL="test@example.com")
class TestUserModel(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(email="User@EXAMPLE.COM")

    def test_pk(self):
        """The primary key is a UUID version 7."""
        self.assertIsInstance(self.user.pk, uuid.UUID)
        self.assertEqual(7, self.user.pk.version)

    def test_unique_email(self):
        """The email field is unique, and case-insensitive."""
        with self.assertRaisesMessage(
            IntegrityError, "duplicate key value violates unique constraint"
        ):
            user_factories.UserFactory(email="USER@Example.COM")

    def test_change_email_unique_constraint(self):
        """Changing the email field should maintain the unique constraint."""
        user = user_factories.UserFactory()  # new user
        with self.assertRaisesMessage(
            IntegrityError, "duplicate key value violates unique constraint"
        ):
            user.email = "UseR@example.com"  # existing user's email, but different case
            user.save(update_fields=["email"])

    def test_str(self):
        """The string representation of the user is the (normalized) email address."""
        self.assertEqual("User@example.com", str(self.user))

    def test_set_password(self):
        """Sets the user's password to the hashed value of the raw password."""
        self.user.set_password("L3tM3In!")
        self.assertTrue(self.user.has_usable_password())
        self.assertTrue(self.user.check_password("L3tM3In!"))

    def test_set_unusable_password(self):
        """Sets the user's password to an unusable value."""
        self.user.set_unusable_password()
        self.assertFalse(self.user.has_usable_password())

    def test_email_user(self):
        """Sends an email to the user."""
        self.user.email_user("Test subject", "Test message")

        self.assertEqual(1, len(mail.outbox))
        email = mail.outbox[0]

        self.assertEqual([self.user.email], email.to)
        self.assertEqual("Test subject", email.subject)
        self.assertEqual("Test message", email.body)
        self.assertEqual("test@example.com", email.from_email)

    def test_get_short_name(self):
        """Returns the first name of the user."""
        user = user_factories.UserFactory(first_name="First", last_name="Last")
        self.assertEqual("First", user.get_short_name())
