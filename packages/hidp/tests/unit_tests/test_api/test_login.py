from http import HTTPStatus

from rest_framework.test import APITestCase

from django.contrib.sessions.backends.db import SessionStore
from django.core import mail
from django.urls import reverse

from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory


class TestLoginView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:login")
        cls.unverified_user = UserFactory()
        cls.verified_user = VerifiedUserFactory()

    def test_login_method_get_not_allowed(self):
        """Tests that a GET request to the login endpoint is not allowed."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_valid_login_unverified_email(self):
        """
        Verify behavior when logging in an user that has not verified their email.

        - No session cookies are set
        - An email verification email is sent
        - The response status code is 401 Unauthorized
        - The response is empty
        """
        response = self.client.post(
            self.url,
            data={
                "username": self.unverified_user.email,
                "password": "P@ssw0rd!",
            },
        )

        cookies = response.cookies
        self.assertNotIn("sessionid", cookies)
        self.assertNotIn("csrftoken", cookies)

        self.assertEqual(len(mail.outbox), 1)

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertIsNone(response.data)

    def test_valid_login_verified_email(self):
        """
        Verify behavior when logging in an user that has verified their email.

        - Session cookies are set
        - The session contains the correct user ID
        - The response status code is 204 No Content
        - The response is empty
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
        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertIsNone(response.data)

    def test_login_invalid_credentials(self):
        """
        Verify behavior when logging in an user with invalid credentials.

        - No session cookies are set
        - An email verification email is not sent
        - The response status code is 400 Bad Request
        - The response contains the correct error message
        """
        with self.subTest("User provides invalid password"):
            response = self.client.post(
                self.url,
                data={
                    "username": self.verified_user.email,
                    "password": "WrongPassword!",
                },
            )

            cookies = response.cookies
            self.assertNotIn("sessionid", cookies)
            self.assertNotIn("csrftoken", cookies)

            self.assertEqual(len(mail.outbox), 0)
            self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
            errors = response.data["non_field_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), "Could not authenticate")

        with self.subTest("User provides invalid email"):
            response = self.client.post(
                self.url,
                data={
                    "username": "WrongEmail@email.com",
                    "password": "P@ssw0rd!",
                },
            )

            cookies = response.cookies
            self.assertNotIn("sessionid", cookies)
            self.assertNotIn("csrftoken", cookies)

            self.assertEqual(len(mail.outbox), 0)
            self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
            errors = response.data["non_field_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), "Could not authenticate")
