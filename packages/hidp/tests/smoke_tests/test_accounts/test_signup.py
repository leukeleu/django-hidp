from http import HTTPStatus

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from hidp.accounts.email_verification import get_email_verification_required_url
from hidp.accounts.forms import UserCreationForm
from hidp.test.factories import user_factories

User = get_user_model()


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

    def test_get_tos(self):
        """The terms of service should be displayed."""
        response = self.client.get(reverse("hidp_accounts:tos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/tos.html")

    def test_tos_required(self):
        """The user should agree to the terms of service."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            },
        )
        self.assertFormError(
            response.context["form"], "agreed_to_tos", "This field is required."
        )

    def test_valid_registration(self):
        """A new user should be created and logged in."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        # Agreed to TOS
        self.assertAlmostEqual(
            timezone.now(),
            user.agreed_to_tos,
            delta=timezone.timedelta(seconds=10),
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(user, next_url="/"),
            fetch_redirect_response=False,
        )

    def test_valid_registration_safe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
                "next": "/example/",
            },
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        self.assertRedirects(
            response,
            get_email_verification_required_url(user, next_url="/example/"),
            fetch_redirect_response=False,
        )

    def test_valid_registration_unsafe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
                "next": "https://example.com/",
            },
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        self.assertRedirects(
            response,
            get_email_verification_required_url(user, next_url="/"),
            fetch_redirect_response=False,
        )

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
