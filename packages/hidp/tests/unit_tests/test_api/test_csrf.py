from http import HTTPStatus

from rest_framework.test import APIClient, APITestCase

from django.core import mail
from django.urls import reverse

from hidp.test.factories.user_factories import VerifiedUserFactory

ANONYMOUS_ENDPOINTS = [
    ("post", "hidp_api:login"),
    ("post", "hidp_api:logout"),
    ("post", "hidp_api:signup"),
    ("post", "hidp_api:email_verification_resend"),
    ("post", "hidp_api:email_verification_verify"),
    ("post", "hidp_api:email_verification_confirm"),
    ("post", "hidp_api:password_reset_request"),
    ("post", "hidp_api:password_reset_confirm"),
    ("post", "hidp_api:oidc_authenticate", {"provider_key": "example"}),
    ("post", "hidp_api:oidc_registration"),
]

AUTHENTICATED_ENDPOINTS = [
    ("post", "hidp_api:logout"),
    ("patch", "hidp_api:user"),
    ("post", "hidp_api:password_change"),
    ("post", "hidp_api:set_password"),
    ("post", "hidp_api:email_change"),
    ("delete", "hidp_api:email_change"),
    ("post", "hidp_api:email_change_confirm"),
    ("post", "hidp_api:oidc_link"),
    ("delete", "hidp_api:oidc_connection", {"provider_key": "example"}),
]


class TestCSRF(APITestCase):
    """Every unsafe request needs a CSRF token, whether or not a user is logged in."""

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

    def _assert_rejected(self, endpoints):
        for method, url_name, *kwargs in endpoints:
            with self.subTest(method=method, url_name=url_name):
                response = getattr(self.client, method)(
                    reverse(url_name, kwargs=kwargs[0] if kwargs else None),
                    {},
                    format="json",
                )
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
                self.assertIn("CSRF Failed", response.json()["detail"])
        self.assertEqual(len(mail.outbox), 0)

    def test_anonymous_requests_need_a_token(self):
        self._assert_rejected(ANONYMOUS_ENDPOINTS)

    def test_authenticated_requests_need_a_token(self):
        self.client.force_login(VerifiedUserFactory())

        self._assert_rejected(AUTHENTICATED_ENDPOINTS)
