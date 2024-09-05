from django.test import TestCase, override_settings

from hidp.accounts import forms
from hidp.test.factories import user_factories


@override_settings(
    LANGUAGE_CODE="en",
    AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"],
)
class TestAuthenticationForm(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def test_is_valid(self):
        form = forms.AuthenticationForm(
            data={"username": self.user.email, "password": "P@ssw0rd!"}
        )
        self.assertTrue(form.is_valid())
        self.assertEqual(form.get_user(), self.user)

    def test_is_invalid(self):
        form = forms.AuthenticationForm(
            data={"username": self.user.email, "password": "wrong"}
        )
        self.assertFalse(form.is_valid())
        self.assertIsNone(form.get_user())
        self.assertFormError(
            form,
            None,
            [
                "Please enter a correct email address and password."
                " Note that both fields may be case-sensitive."
            ],
        )

    def test_is_inactive(self):
        self.user.is_active = False
        self.user.save()

        with self.subTest("Default backend"):
            form = forms.AuthenticationForm(
                data={"username": self.user.email, "password": "P@ssw0rd!"}
            )
            self.assertFalse(form.is_valid())
            # The user is not authenticated.
            self.assertIsNone(form.get_user())
            self.assertFormError(
                form,
                None,
                [
                    "Please enter a correct email address and password."
                    " Note that both fields may be case-sensitive."
                ],
            )

        with (
            self.subTest("AllowAllUsersModelBackend"),
            override_settings(
                AUTHENTICATION_BACKENDS=[
                    "django.contrib.auth.backends.AllowAllUsersModelBackend"
                ]
            ),
        ):
            form = forms.AuthenticationForm(
                data={"username": self.user.email, "password": "P@ssw0rd!"}
            )
            self.assertFalse(form.is_valid())
            # The user is authenticated, but not allowed to log in.
            self.assertEqual(form.get_user(), self.user)
            self.assertFormError(form, None, ["This account is inactive."])


class TestOptionalTOSUserCreationFormForm(TestCase):
    @classmethod
    def setUpTestData(cls):
        class NoTOSUserCreationForm(forms.UserCreationForm):
            """UserCreationForm without the agreed_to_tos field."""

            agreed_to_tos = None

        cls.form = NoTOSUserCreationForm

    def test_save(self):
        """Does not set agreed_to_tos on the user."""
        form = self.form(
            data={
                "email": "info@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            }
        )
        self.assertTrue(form.is_valid())
        user = form.save()
        self.assertIsNone(user.agreed_to_tos)
