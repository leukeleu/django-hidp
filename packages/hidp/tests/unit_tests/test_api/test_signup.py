from http import HTTPStatus

from rest_framework.test import APITestCase

from django.core import mail
from django.test import override_settings
from django.urls import reverse

from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory

EMAIL_VERIFY_STATE = {"user": None, "pending": [{"step": "email_verify"}]}


class TestSignupView(APITestCase):
    """Signing up responds the same way whether or not the account exists."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:signup")

    def _signup(self, email="walter@example.com", **data):
        return self.client.post(
            self.url,
            {
                "email": email,
                "password": "P@ssw0rd!",
                "agreed_to_tos": True,
            }
            | data,
            format="json",
        )

    def test_new_account(self):
        response = self._signup()

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(response.json(), EMAIL_VERIFY_STATE)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Verify your email address")
        self.assertIn("http://testserver/frontend/verify/", mail.outbox[0].body)

    def test_next_is_in_the_verification_link(self):
        """The client continues at `next` after verifying, such as an authorization."""
        self._signup(next="/o/authorize/?client_id=app&scope=openid")

        self.assertRegex(
            mail.outbox[0].body,
            r"http://testserver/frontend/verify/\S+/"
            r"\?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dapp%26scope%3Dopenid",
        )

    def test_absolute_next_on_this_host(self):
        # Django OAuth Toolkit sends prompt=create with an absolute `next`.
        self._signup(next="http://testserver/o/authorize/?client_id=app")

        self.assertIn(
            "?next=%2Fo%2Fauthorize%2F%3Fclient_id%3Dapp", mail.outbox[0].body
        )

    def test_next_on_another_host(self):
        response = self._signup(next="https://evil.example.com/")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("next", response.json())
        self.assertEqual(len(mail.outbox), 0)

    def test_new_account_is_not_logged_in(self):
        self._signup()

        self.assertNotIn("_auth_user_id", self.client.session)

    def test_existing_unverified_account(self):
        UserFactory(email="walter@example.com")

        response = self._signup()

        self.assertEqual(response.json(), EMAIL_VERIFY_STATE)
        self.assertEqual(mail.outbox[0].subject, "Verify your email address")

    def test_existing_verified_account(self):
        VerifiedUserFactory(email="walter@example.com")

        response = self._signup(email="WALTER@example.com")

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(response.json(), EMAIL_VERIFY_STATE)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("http://testserver/frontend/reset/", mail.outbox[0].body)

    def test_existing_verified_account_is_not_sent_verification_on_resend(self):
        VerifiedUserFactory(email="walter@example.com")
        self._signup()

        response = self.client.post(reverse("hidp_api:email_verification_resend"))

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(
        AUTH_PASSWORD_VALIDATORS=[
            {"NAME": ("django.contrib.auth.password_validation.MinimumLengthValidator")}
        ]
    )
    def test_form_errors_use_serializer_field_names(self):
        response = self._signup(password="short", agreed_to_tos=False)

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(set(response.json()), {"password", "agreed_to_tos"})

    def test_authenticated_user_cannot_sign_up(self):
        self.client.force_login(VerifiedUserFactory())

        response = self._signup()

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "already_authenticated")

    @override_settings(REGISTRATION_ENABLED=False)
    def test_registration_disabled(self):
        response = self._signup()

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(len(mail.outbox), 0)
