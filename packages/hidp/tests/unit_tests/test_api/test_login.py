from http import HTTPStatus
from unittest import mock

from rest_framework.response import Response
from rest_framework.test import APIClient, APITestCase

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_login_failed
from django.contrib.sessions.backends.db import SessionStore
from django.core import mail
from django.db import connection
from django.test import override_settings
from django.urls import reverse

from hidp.api.auth_state import EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY
from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory

UserModel = get_user_model()


class TestLoginView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:login")
        cls.unverified_user = UserFactory()
        cls.verified_user = VerifiedUserFactory()

    def test_next_is_in_the_verification_link(self):
        self.client.post(
            self.url,
            {
                "username": self.unverified_user.email,
                "password": "P@ssw0rd!",
                "next": "/somewhere/",
            },
            format="json",
        )

        self.assertIn("?next=%2Fsomewhere%2F", mail.outbox[0].body)

    def test_login_method_get_not_allowed(self):
        """Tests that a GET request to the login endpoint is not allowed."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_valid_login_unverified_email(self):
        """
        Verify behavior when logging in an user that has not verified their email.

        - The user is not logged in
        - An email verification email is sent
        - The session remembers the pending verification
        - The response is 401 with the pending email verification step
        """
        response = self.client.post(
            self.url,
            data={
                "username": self.unverified_user.email,
                "password": "P@ssw0rd!",
            },
        )

        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertIn(EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY, self.client.session)

        self.assertEqual(len(mail.outbox), 1)
        self.assertRegex(
            mail.outbox[0].body,
            r"http://testserver/frontend/verify/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "email_verify"}]}
        )

    def test_unverified_login_logs_out_the_current_user(self):
        self.client.force_login(self.verified_user)

        response = self.client.post(
            self.url,
            data={
                "username": self.unverified_user.email,
                "password": "P@ssw0rd!",
            },
        )

        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertIn(EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY, self.client.session)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "email_verify"}]}
        )

    def test_valid_login_verified_email(self):
        """
        Verify behavior when logging in an user that has verified their email.

        - Session cookies are set
        - The session contains the correct user ID
        - The response is 200 with the user and no pending steps
        """
        response = self.client.post(
            self.url,
            data={
                "username": self.verified_user.email,
                "password": "P@ssw0rd!",
            },
        )

        cookies = response.cookies
        self.assertIn("sessionid", cookies)
        self.assertIn("csrftoken", cookies)

        session = SessionStore(session_key=cookies["sessionid"].value)
        self.assertEqual(session["_auth_user_id"], str(self.verified_user.id))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(
            response.json(),
            {
                "user": {
                    "id": str(self.verified_user.id),
                    "first_name": self.verified_user.first_name,
                    "last_name": self.verified_user.last_name,
                    "email": self.verified_user.email,
                    "has_usable_password": True,
                },
                "pending": [],
            },
        )

    def test_login_with_csrf_token_from_session(self):
        client = APIClient(enforce_csrf_checks=True)
        client.get(reverse("hidp_api:session"))

        response = client.post(
            self.url,
            data={"username": self.verified_user.email, "password": "P@ssw0rd!"},
            headers={"X-CSRFToken": client.cookies["csrftoken"].value},
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_login_invalid_credentials(self):
        """
        Verify behavior when logging in an user with invalid credentials.

        - No session cookies are set
        - An email verification email is not sent
        - The response status code is 400 Bad Request
        - The response contains the correct error message
        """
        for username, password in [
            (self.verified_user.email, "WrongPassword!"),
            ("WrongEmail@email.com", "P@ssw0rd!"),
        ]:
            with self.subTest(username=username, password=password):
                response = self.client.post(
                    self.url, data={"username": username, "password": password}
                )

                self.assertNotIn("sessionid", response.cookies)
                self.assertNotIn("csrftoken", response.cookies)
                self.assertEqual(len(mail.outbox), 0)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
                self.assertEqual(
                    response.json(),
                    {
                        "non_field_errors": [
                            (
                                "Please enter a correct email address and password."
                                " Note that both fields may be case-sensitive."
                            )
                        ]
                    },
                )


class TestLoginUnderAtomicRequests(APITestCase):
    """A rejected login keeps the writes made while checking it."""

    def test_failed_login_is_not_rolled_back(self):
        def record_failure(**kwargs):
            UserFactory(email="failure@example.com")

        user_login_failed.connect(record_failure)
        self.addCleanup(user_login_failed.disconnect, record_failure)

        with mock.patch.dict(connection.settings_dict, {"ATOMIC_REQUESTS": True}):
            response = self.client.post(
                reverse("hidp_api:login"),
                {"username": "walter@example.com", "password": "wrong"},
                format="json",
            )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertTrue(UserModel.objects.filter(email="failure@example.com").exists())


def project_exception_handler(exc, context):
    return Response({"wrapped": True}, status=HTTPStatus.BAD_REQUEST)


class TestProjectExceptionHandler(APITestCase):
    """The API keeps its documented errors under a project-wide exception handler."""

    @override_settings(
        REST_FRAMEWORK={
            "EXCEPTION_HANDLER": (
                "tests.unit_tests.test_api.test_login.project_exception_handler"
            )
        }
    )
    def test_errors_keep_their_shape(self):
        response = self.client.post(
            reverse("hidp_api:login"), {"username": "walter@example.com"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("password", response.json())
