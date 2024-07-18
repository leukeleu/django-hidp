from django.test import TestCase

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
