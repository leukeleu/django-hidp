from http import HTTPStatus

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
            response, "accounts/verification/email_verification_required.html"
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
        """
        Works when the token is considered valid.
        """
        self._assert_response(self.client.get(self.url))

    def test_get_invalid_token(self):
        """
        Invalid token.
        """
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "invalid-value:invalid-signature"},
            )
        )
        self._assert_response(response, validlink=False)
