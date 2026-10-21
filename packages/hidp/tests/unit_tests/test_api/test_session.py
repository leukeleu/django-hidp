from http import HTTPStatus

from rest_framework.test import APITestCase

from django.urls import reverse

from hidp.accounts import tokens
from hidp.api.auth_state import EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY
from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory


class TestSessionView(APITestCase):
    """The session endpoint describes the authentication state of the session."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:session")

    def test_anonymous(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(response.json(), {"user": None, "pending": []})

    def test_sets_csrf_cookie(self):
        response = self.client.get(self.url)

        self.assertIn("csrftoken", response.cookies)

    def test_is_never_cached(self):
        response = self.client.get(self.url)

        self.assertIn("no-store", response["Cache-Control"])

    def test_authenticated(self):
        user = VerifiedUserFactory()
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(
            response.json(),
            {
                "user": {
                    "id": str(user.id),
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "has_usable_password": True,
                },
                "pending": [],
            },
        )

    def test_pending_email_verification(self):
        user = UserFactory()
        session = self.client.session
        session[EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY] = (
            tokens.email_verification_request_token_generator.make_token(user)
        )
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "email_verify"}]}
        )

    def test_pending_email_verification_with_invalid_token(self):
        session = self.client.session
        session[EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY] = "invalid"
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.json(), {"user": None, "pending": []})
