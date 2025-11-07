from http import HTTPStatus

from rest_framework.test import APIClient, APITestCase

from django.core import mail
from django.urls import reverse

from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory


class TestEmailVerifiedView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:email_verified")
        cls.client = APIClient(enforce_csrf_checks=True)
        cls.unverified_user = UserFactory()
        cls.verified_user = VerifiedUserFactory()

    def test_email_verified_requires_authentication(self):
        """Verify that authentication is required to access the email verified endpoint."""  # noqa: E501, W505
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_email_verified_unverified_user(self):
        """Verify that the email verified status is False for an unverified user."""
        self.client.force_login(self.unverified_user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), {"email_verified": False})

    def test_email_verified_verified_user(self):
        """Verify that the email verified status is True for a verified user."""
        self.client.force_login(self.verified_user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), {"email_verified": True})


class TestEmailVerificationResendView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:email_verified_resend")
        cls.client = APIClient(enforce_csrf_checks=True)
        cls.unverified_user = UserFactory()
        cls.verified_user = VerifiedUserFactory()

    def test_email_verification_resend_requires_authentication(self):
        """Verify that authentication is required to resend email verification."""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_email_verified_unverified_user(self):
        """Verify that an email is sent to an unverified user."""
        self.client.force_login(self.unverified_user)
        response = self.client.post(self.url)

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertIsNone(response.data)

    def test_email_verified_for_already_verified_user(self):
        """Verify that a ValidationError is raised for an already verified user."""
        self.client.force_login(self.verified_user)
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("Email is already verified.", response.json())
