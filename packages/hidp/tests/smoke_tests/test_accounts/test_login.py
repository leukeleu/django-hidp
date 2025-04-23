from unittest import mock

from django.core import mail
from django.test import TestCase, override_settings
from django.test.client import ClientHandler
from django.urls import reverse

from hidp.accounts import auth as hidp_auth
from hidp.accounts.forms import AuthenticationForm, RateLimitedAuthenticationForm
from hidp.test.factories import user_factories


class RateLimitedHandler(ClientHandler):
    def get_response(self, request):
        request.limited = True
        return super().get_response(request)


@override_settings(LOGIN_REDIRECT_URL="/", LANGUAGE_CODE="en")
class TestLogin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()
        cls.login_url = reverse("hidp_accounts:login")

    def test_get_login(self):
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], AuthenticationForm)

    @mock.patch("hidp.accounts.views.hidp_auth.login", wraps=hidp_auth.login)
    def test_valid_login_wrapped_login_function(self, mock_login):
        self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
            },
        )
        mock_login.assert_called_once()

    @mock.patch("hidp.accounts.views.hidp_auth.login", wraps=hidp_auth.login)
    def test_valid_login_unverified_email(self, mock_login):
        user = user_factories.UserFactory()
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.login_url,
                {
                    "username": user.email,
                    "password": "P@ssw0rd!",
                },
                follow=True,
            )
        # Does not log in the user
        mock_login.assert_not_called()
        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "Verification required",
            response.content.decode("utf-8"),
        )

    def test_valid_login_default_redirect(self):
        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_valid_login_safe_next_param(self):
        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
                "next": "/example/",
            },
        )
        self.assertRedirects(response, "/example/", fetch_redirect_response=False)

    def test_valid_login_unsafe_next_param(self):
        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
                "next": "https://example.com/",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_invalid_login(self):
        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "invalid",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], AuthenticationForm)
        self.assertFormError(
            response.context["form"],
            None,
            (
                "Please enter a correct email address and password."
                " Note that both fields may be case-sensitive."
            ),
        )

    def test_rate_limited_login(self):
        self.client.handler = RateLimitedHandler(enforce_csrf_checks=False)
        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], RateLimitedAuthenticationForm)
        self.assertFormError(
            response.context["form"],
            "i_am_not_a_robot",
            ("Please confirm that you are not a robot."),
        )

        response = self.client.post(
            self.login_url,
            {
                "username": self.user.email,
                "password": "P@ssw0rd!",
                "i_am_not_a_robot": "on",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)
