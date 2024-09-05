from datetime import timedelta
from unittest import mock

from django.contrib.auth import SESSION_KEY, get_user, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils import timezone

from hidp.accounts import auth
from hidp.test.factories import user_factories


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
            email=self.user.email,
            password="P@ssw0rd!",
        )

        self.assertEqual(user, self.user)
        self.assertEqual(user.backend, "django.contrib.auth.backends.ModelBackend")
        self.assertNotIn(SESSION_KEY, self.request.session)

    @mock.patch(
        "django.contrib.auth.signals.user_login_failed.send",
        wraps=user_login_failed.send,
    )
    def test_invalid_credentials(self, mock_user_login_failed):
        """
        Returns None if the credentials are invalid.

        Then sends the `django.contrib.auth.user_login_failed` signal.
        """
        user = auth.authenticate(
            request=self.request,
            email=self.user.email,
            password="invalid",
        )

        self.assertIsNone(user)
        mock_user_login_failed.assert_called_once_with(
            sender="django.contrib.auth",
            request=self.request,
            credentials={"email": self.user.email, "password": "*" * 20},
        )

    @mock.patch(
        "django.contrib.auth.signals.user_login_failed.send",
        wraps=user_login_failed.send,
    )
    def test_permission_denied(self, mock_user_login_failed):
        """
        Returns None if the user is not allowed to log in.

        Then sends the `django.contrib.auth.user_login_failed` signal.
        """
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        user = auth.authenticate(
            request=self.request,
            email=self.user.email,
            password="P@ssw0rd!",
        )

        self.assertIsNone(user)
        mock_user_login_failed.assert_called_once_with(
            sender="django.contrib.auth",
            request=self.request,
            credentials={"email": self.user.email, "password": "*" * 20},
        )


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
    ]
)
class TestLogin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def setUp(self):
        self.request = HttpRequest()
        self.request.session = self.client.session

    @mock.patch(
        "django.contrib.auth.signals.user_logged_in.send", wraps=user_logged_in.send
    )
    def test_success(self, mock_user_logged_in):
        """Logs in the user and sets the user in the request's session."""
        auth.login(self.request, self.user)

        self.assertEqual(self.request.session[SESSION_KEY], str(self.user.pk))
        mock_user_logged_in.assert_called_once_with(
            sender=get_user_model(),
            request=self.request,
            user=self.user,
        )

        self.user.refresh_from_db()
        self.assertAlmostEqual(
            self.user.last_login, timezone.now(), delta=timedelta(seconds=1)
        )

    @mock.patch(
        "django.contrib.auth.signals.user_logged_in.send", wraps=user_logged_in.send
    )
    def test_inactive_user(self, mock_user_logged_in):
        """Does not verify that the user is allowed to log in."""
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        auth.login(self.request, self.user)

        self.assertEqual(self.request.session[SESSION_KEY], str(self.user.pk))
        mock_user_logged_in.assert_called_once_with(
            sender=get_user_model(),
            request=self.request,
            user=self.user,
        )

        self.user.refresh_from_db()
        self.assertAlmostEqual(
            self.user.last_login, timezone.now(), delta=timedelta(seconds=1)
        )

        # `django.contrib.auth.get_user` **does** verify that the user is
        # allowed to log in and returns an `AnonymousUser` instance.
        # This results in `request.user` being an `AnonymousUser` on the next
        # request, once `AuthenticationMiddleware` has processed the request.
        self.assertIsInstance(get_user(self.request), AnonymousUser)

    def test_none_user(self):
        """
        User may be None, and in some cases this will **not** cause an exception.

        This is unexpected behaviour, see also:
        https://code.djangoproject.com/ticket/35530#comment:1

        The wrapped `django.contrib.auth.login` function raises an exception if the user
        is not an instance of `AbstractBaseUser`.
        """
        with (
            self.subTest("request.user is absent"),
            self.assertRaisesMessage(
                TypeError, "'NoneType' does not extend AbstractBaseUser"
            ),
        ):
            auth.login(self.request, None)

        with self.subTest("Current user is None"):
            self.request.user = None
            with self.assertRaisesMessage(
                TypeError, "'NoneType' does not extend AbstractBaseUser"
            ):
                auth.login(self.request, None)

        with self.subTest("Current user is AnonymousUser"):
            self.request.user = AnonymousUser()
            with self.assertRaisesMessage(
                TypeError, "'NoneType' does not extend AbstractBaseUser"
            ):
                auth.login(self.request, None)

        # Edge case, Django uses the current user here, HIdP does not.

        with self.subTest("Current user is not None"):
            # Will log in the current user (again) for some reason.
            user = user_factories.UserFactory()
            self.request.user = user

            with self.assertRaisesMessage(
                TypeError, "'NoneType' does not extend AbstractBaseUser"
            ):
                auth.login(self.request, None)


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
    ]
)
class TestLogout(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def setUp(self):
        self.request = HttpRequest()
        self.request.session = self.client.session
        self.request.user = AnonymousUser()

    @mock.patch(
        "django.contrib.auth.signals.user_logged_out.send",
        wraps=user_logged_out.send,
    )
    def test_logout_without_login(self, mock_user_logged_out):
        """Resets the session regardless of whether a user is logged in."""
        self.request.session["test"] = "test"
        session_key = self.request.session.session_key
        auth.logout(self.request)

        self.assertNotEqual(session_key, self.request.session.session_key)
        self.assertNotIn("test", self.request.session)
        mock_user_logged_out.assert_called_once_with(
            sender=type(None),  # Weird, but that's what Django does.
            request=self.request,
            user=None,
        )
        self.assertIsInstance(self.request.user, AnonymousUser)

    @mock.patch(
        "django.contrib.auth.signals.user_logged_out.send",
        wraps=user_logged_out.send,
    )
    def test_logout_after_login(self, mock_user_logged_out):
        """Logs out the user and removes the user from the request's session."""
        # Log in the user.
        auth.login(self.request, self.user)
        session_key = self.request.session.session_key
        self.assertEqual(self.request.session[SESSION_KEY], str(self.user.pk))

        # Log out the user.
        auth.logout(self.request)

        self.assertNotEqual(session_key, self.request.session.session_key)
        self.assertNotIn(SESSION_KEY, self.request.session)
        mock_user_logged_out.assert_called_once_with(
            sender=get_user_model(),
            request=self.request,
            user=self.user,
        )
        self.assertIsInstance(self.request.user, AnonymousUser)
