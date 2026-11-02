from unittest import mock

from django.test import TestCase
from django.urls import reverse

from hidp.accounts import views
from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory


class TestSendEmailHooks(TestCase):
    """The HTML views send their emails through an overridable `send_email`."""

    def _post(self, view_class, url_name, data):
        with mock.patch.object(view_class, "send_email") as send_email:
            self.client.post(reverse(url_name), data)
        return send_email

    def test_registration(self):
        send_email = self._post(
            views.RegistrationView,
            "hidp_accounts:register",
            {
                "email": "walter@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
        )
        send_email.assert_called_once()

    def test_login_with_unverified_email(self):
        user = UserFactory()
        send_email = self._post(
            views.LoginView,
            "hidp_accounts:login",
            {"username": user.email, "password": "P@ssw0rd!"},
        )
        send_email.assert_called_once_with(user)

    def test_password_reset_request(self):
        user = VerifiedUserFactory()
        send_email = self._post(
            views.PasswordResetRequestView,
            "hidp_accounts:password_reset_request",
            {"email": user.email},
        )
        send_email.assert_called_once_with(user)

    def test_password_change(self):
        self.client.force_login(VerifiedUserFactory())
        send_email = self._post(
            views.PasswordChangeView,
            "hidp_account_management:change_password",
            {
                "old_password": "P@ssw0rd!",
                "new_password1": "N3wP@ssw0rd!",
                "new_password2": "N3wP@ssw0rd!",
            },
        )
        send_email.assert_called_once_with()
