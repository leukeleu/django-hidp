from django.test import TestCase

from hidp.test.factories import user_factories
from tests.custom_user.models import CustomUser


class TestUserManager(TestCase):
    def test_create_user_requires_email(self):
        with self.assertRaises(ValueError) as cm:
            CustomUser.objects.create_user(email=None)
        self.assertEqual("User must have an email address", str(cm.exception))

    def test_creates_normal_users(self):
        """
        Create a normal user with the given email address.

        The email address should be normalized, the password should be hashed,
        and the user should not be a staff member or a superuser.
        """
        user = CustomUser.objects.create_user(
            email="info@EXAMPLE.COM", password="P@ssw0rd!"
        )
        self.assertEqual(user.email, "info@example.com")
        self.assertTrue(
            user.has_usable_password(), msg="Expected user to have a usable password"
        )
        self.assertTrue(
            user.check_password("P@ssw0rd!"), msg="Expected password to match"
        )
        self.assertFalse(user.is_staff, msg="Expected is_staff to be False")
        self.assertFalse(user.is_superuser, msg="Expected is_superuser to be False")

    def test_creates_superusers(self):
        superuser = CustomUser.objects.create_superuser(
            email="info@EXAMPLE.COM", password="P@ssw0rd!"
        )
        self.assertEqual(superuser.email, "info@example.com")
        self.assertTrue(
            superuser.has_usable_password(),
            msg="Expected user to have a usable password",
        )
        self.assertTrue(
            superuser.check_password("P@ssw0rd!"), msg="Expected password to match"
        )
        self.assertTrue(superuser.is_staff, msg="Expected is_staff to be True")
        self.assertTrue(superuser.is_superuser, msg="Expected is_superuser to be True")

    def test_email_unverified(self):
        """Return a queryset of users that have not verified their email address."""
        unverified_user = user_factories.UserFactory()
        user_factories.VerifiedUserFactory()
        user_factories.SuperUserFactory()
        self.assertQuerySetEqual(
            CustomUser.objects.email_unverified(),
            [repr(unverified_user)],
            transform=repr,
            ordered=False,
        )

    def test_email_verified(self):
        """Return a queryset of users that have verified their email address."""
        user_factories.UserFactory()
        verified_user = user_factories.VerifiedUserFactory()
        superuser = user_factories.SuperUserFactory()
        self.assertQuerySetEqual(
            CustomUser.objects.email_verified(),
            [repr(verified_user), repr(superuser)],
            transform=repr,
            ordered=False,
        )
