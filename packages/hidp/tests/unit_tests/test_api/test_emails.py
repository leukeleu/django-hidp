from http import HTTPStatus

from rest_framework.test import APIClient, APITestCase

from django.core import mail
from django.urls import reverse

from hidp.accounts import tokens
from hidp.api.auth_state import EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY
from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory

VERIFICATION_URL_PATTERN = (
    r"http://testserver/frontend/verify/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/"
)


class TestEmailVerificationResendView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:email_verification_resend")
        cls.unverified_user = UserFactory()

    def _start_verification(self, user, client=None):
        session = (client or self.client).session
        session[EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY] = (
            tokens.email_verification_request_token_generator.make_token(user)
        )
        session.save()

    def test_resend_without_pending_verification(self):
        """Nothing is sent, and the response does not reveal it."""
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 0)

    def test_resend_for_pending_verification(self):
        """The verification email is sent to the user the session is waiting for."""
        self._start_verification(self.unverified_user)

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Verify your email address")
        self.assertEqual(email.to, [self.unverified_user.email])
        self.assertRegex(email.body, VERIFICATION_URL_PATTERN)

    def test_resend_after_user_verified(self):
        """A user who verified in the meantime does not get another email."""
        user = VerifiedUserFactory()
        self._start_verification(user)

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 0)

    def test_resend_requires_csrf_token(self):
        client = APIClient(enforce_csrf_checks=True)
        self._start_verification(self.unverified_user, client=client)

        response = client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(len(mail.outbox), 0)


class TestEmailVerificationVerifyView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:email_verification_verify")

    def test_invalid_token(self):
        response = self.client.post(self.url, {"token": "invalid"})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("token", response.json())

    def test_token_of_verified_user(self):
        user = VerifiedUserFactory()
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_user_with_name(self):
        user = UserFactory()
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), {"requires_name": False})

    def test_user_without_name(self):
        # Users created through an OIDC provider may not have a name yet.
        user = UserFactory(first_name="", last_name="")
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), {"requires_name": True})

    def test_request_token_is_not_accepted(self):
        """The token from the session cannot be used in place of the emailed token."""
        user = UserFactory()
        token = tokens.email_verification_request_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)


class TestEmailVerificationConfirmView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:email_verification_confirm")

    def test_confirm_marks_email_verified(self):
        user = UserFactory()
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        user.refresh_from_db()
        self.assertIsNotNone(user.email_verified)

    def test_confirm_does_not_log_in(self):
        user = UserFactory()
        token = tokens.email_verification_token_generator.make_token(user)

        self.client.post(self.url, {"token": token})

        self.assertNotIn("_auth_user_id", self.client.session)

    def test_confirm_twice(self):
        user = UserFactory()
        token = tokens.email_verification_token_generator.make_token(user)
        self.client.post(self.url, {"token": token})

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_confirm_requires_name_when_missing(self):
        user = UserFactory(first_name="", last_name="")
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(set(response.json()), {"first_name", "last_name"})
        user.refresh_from_db()
        self.assertIsNone(user.email_verified)

    def test_confirm_stores_name_when_missing(self):
        user = UserFactory(first_name="", last_name="")
        token = tokens.email_verification_token_generator.make_token(user)

        response = self.client.post(
            self.url,
            {"token": token, "first_name": "Jesse", "last_name": "Pinkman"},
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ("Jesse", "Pinkman"))
        self.assertIsNotNone(user.email_verified)

    def test_confirm_invalid_token(self):
        response = self.client.post(self.url, {"token": "invalid"})

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
