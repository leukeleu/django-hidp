from http import HTTPStatus

from django.test import TestCase, override_settings
from django.urls import reverse

from hidp.accounts.forms import UserCreationForm
from hidp.test.factories import user_factories


@override_settings(
    LANGUAGE_CODE="en",
)
class TestRegistrationView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = user_factories.UserFactory()
        cls.signup_url = reverse("hidp_accounts:register")

    def test_get(self):
        """The registration form should be displayed."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/register.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], UserCreationForm)

    def test_valid_registration(self):
        """A new user should be created and logged in."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        # User should be created and logged in
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertEqual(response.wsgi_request.user.email, "test@example.com")

    def test_valid_registration_safe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "next": "/example/",
            },
        )
        self.assertRedirects(response, "/example/", fetch_redirect_response=False)

    def test_valid_registration_unsafe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "next": "https://example.com/",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_duplicate_email(self):
        """A user should not be able to sign up with an existing email."""
        response = self.client.post(
            self.signup_url,
            {
                "email": self.test_user.email,
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            },
        )
        self.assertFormError(
            response.context["form"],
            "email",
            "User with this Email address already exists.",
        )

    def test_with_logged_in_user(self):
        """A logged-in user should not be able to sign up again."""
        self.client.force_login(self.test_user)
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            },
        )
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
