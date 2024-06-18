from unittest import mock

from django.contrib.auth import SESSION_KEY
from django.contrib.auth.signals import user_login_failed
from django.http import HttpRequest
from django.test import TestCase, override_settings

from hidp.accounts import auth
from tests.factories import user_factories


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
    ]
)
class TestAuthenticate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def setUp(self):
        self.request = HttpRequest()
        self.request.session = self.client.session

    def test_success(self):
        """
        Returns the user object if the credentials are valid.
        Does not log in the user.
        """

        user = auth.authenticate(
            request=self.request,
            username=self.user.username,
            password="P@ssw0rd!",
        )

        self.assertEqual(user, self.user)
        self.assertEqual(user.backend, "django.contrib.auth.backends.ModelBackend")
        self.assertNotIn(SESSION_KEY, self.request.session)

    @mock.patch(
        "django.contrib.auth.signals.user_login_failed.send",
        wraps=user_login_failed.send,
    )
    def test_invalid_credentials(self, user_login_failed):
        """
        Returns None if the credentials are invalid and sends the
        `django.contrib.auth.user_login_failed` signal.
        """

        user = auth.authenticate(
            request=self.request,
            username=self.user.username,
            password="invalid",
        )

        self.assertIsNone(user)
        user_login_failed.assert_called_once_with(
            sender="django.contrib.auth",
            request=self.request,
            credentials={"username": self.user.username, "password": "*" * 20},
        )

    @mock.patch(
        "django.contrib.auth.signals.user_login_failed.send",
        wraps=user_login_failed.send,
    )
    def test_permission_denied(self, user_login_failed):
        """
        Returns None if the user is not allowed to log in and sends the
        `django.contrib.auth.user_login_failed` signal.
        """

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        user = auth.authenticate(
            request=self.request,
            username=self.user.username,
            password="P@ssw0rd!",
        )

        self.assertIsNone(user)
        user_login_failed.assert_called_once_with(
            sender="django.contrib.auth",
            request=self.request,
            credentials={"username": self.user.username, "password": "*" * 20},
        )
