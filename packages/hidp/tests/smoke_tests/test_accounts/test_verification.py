from http import HTTPStatus

from django.core import mail
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from hidp.accounts import tokens
from hidp.test.factories import user_factories


class TestEmailVerificationRequiredView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse(
            "hidp_accounts:email_verification_required",
            kwargs={
                "token": tokens.email_verification_request_token_generator.make_token(
                    cls.user
                )
            },
        )

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(
            response, "hidp/accounts/verification/email_verification_required.html"
        )
        self.assertIn("validlink", response.context)
        if validlink:
            self.assertTrue(
                response.context["validlink"], msg="Expected the link to be valid."
            )
        else:
            self.assertFalse(
                response.context["validlink"], msg="Expected the link to be invalid."
            )

    def test_valid_get(self):
        """Works when the token is considered valid."""
        self._assert_response(self.client.get(self.url, follow=True))

    def test_get_invalid_token(self):
        """Invalid token."""
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_no_token_in_session(self):
        """Placeholder token, no token in session."""
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "email"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_post(self):
        """Send the verification email."""
        # Get the page first, to populate the session
        response = self.client.get(self.url, follow=True)
        # Post to the redirected URL
        self.client.post(response.redirect_chain[-1][0], follow=True)
        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )

    def test_post_invalid_token(self):
        """Does not send the verification email when the token is invalid."""
        # Get the page first, to populate the session
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        # Post to the redirected URL
        self.client.post(response.redirect_chain[-1][0], follow=True)
        # Verification email not sent
        self.assertEqual(len(mail.outbox), 0)


class TestEmailVerificationView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse(
            "hidp_accounts:verify_email",
            kwargs={
                "token": tokens.email_verification_token_generator.make_token(cls.user)
            },
        )

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(
            response, "hidp/accounts/verification/verify_email.html"
        )
        self.assertIn("validlink", response.context)
        if validlink:
            self.assertTrue(
                response.context["validlink"], msg="Expected the link to be valid."
            )
        else:
            self.assertFalse(
                response.context["validlink"], msg="Expected the link to be invalid."
            )

    def test_valid_get(self):
        """Works when the token is considered valid."""
        self._assert_response(self.client.get(self.url, follow=True))

    def test_get_invalid_token(self):
        """Invalid token."""
        response = self.client.get(
            reverse(
                "hidp_accounts:verify_email",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_no_token_in_session(self):
        """Placeholder token, no token in session."""
        response = self.client.get(
            reverse(
                "hidp_accounts:verify_email",
                kwargs={"token": "email"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_inactive_user(self):
        """Inactive user."""
        self.user.is_active = False
        self.user.save()
        response = self.client.get(self.url, follow=True)
        self._assert_response(response, validlink=False)

    def test_already_verified_user(self):
        """Already verified user."""
        self.user.email_verified = timezone.now()
        self.user.save()
        response = self.client.get(self.url, follow=True)
        self._assert_response(response, validlink=False)

    def test_post(self):
        """Update the user's email_verified field."""
        # Get the page first, to populate the session
        response = self.client.get(self.url, follow=True)
        # Post to the redirected URL
        response = self.client.post(response.redirect_chain[-1][0], follow=True)
        self.user.refresh_from_db()
        self.assertIsNotNone(
            self.user.email_verified, msg="Expected email to be verified."
        )
        self.assertAlmostEqual(
            self.user.email_verified,
            timezone.now(),
            delta=timezone.timedelta(seconds=5),
        )
        self.assertURLEqual(
            response.redirect_chain[-1][0],
            reverse("hidp_accounts:email_verification_complete"),
        )
