from django.test import TestCase, override_settings
from django.urls import reverse

from hidp.accounts.forms import AuthenticationForm
from tests.factories import user_factories


@override_settings(
    LOGIN_REDIRECT_URL="/",
    LANGUAGE_CODE="en",
)
class TestLogin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def test_get_login(self):
        response = self.client.get(reverse("auth:login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/login.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], AuthenticationForm)

    def test_valid_login_default_redirect(self):
        response = self.client.post(
            reverse("auth:login"),
            {
                "username": self.user.username,
                "password": "P@ssw0rd!",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_valid_login_safe_next_param(self):
        response = self.client.post(
            f"{reverse('auth:login')}",
            {
                "username": self.user.username,
                "password": "P@ssw0rd!",
                "next": "/example/",
            },
        )
        self.assertRedirects(response, "/example/", fetch_redirect_response=False)

    def test_valid_login_unsafe_next_param(self):
        response = self.client.post(
            f"{reverse('auth:login')}",
            {
                "username": self.user.username,
                "password": "P@ssw0rd!",
                "next": "https://example.com/",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_invalid_login(self):
        response = self.client.post(
            reverse("auth:login"),
            {
                "username": self.user.username,
                "password": "invalid",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/login.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], AuthenticationForm)
        self.assertFormError(
            response.context["form"],
            None,
            (
                "Please enter a correct username and password."
                " Note that both fields may be case-sensitive."
            ),
        )
