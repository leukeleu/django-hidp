from hashlib import sha256
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from oauth2_provider.models import get_application_model

from django.conf import settings
from django.core.signing import b64_encode
from django.test import TestCase, override_settings
from django.urls import reverse

from hidp.test.factories import user_factories

Application = get_application_model()

FRONTEND_URLS = settings.HIDP_FRONTEND_URLS | {
    "oidc_provider_consent": "/frontend/consent/",
    "oidc_provider_logout": "/frontend/logout/",
}


@override_settings(HIDP_FRONTEND_URLS=FRONTEND_URLS)
class TestFrontendPages(TestCase):
    """The frontend shows the pages of the OIDC provider, and posts their forms."""

    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()
        cls.application = Application.objects.create(
            name="Shady App",
            client_id="shady-app",
            client_type=Application.CLIENT_PUBLIC,
            client_secret="",
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=False,
            redirect_uris="https://127.0.0.1/",
            algorithm=Application.RS256_ALGORITHM,
        )

    def setUp(self):
        self.client.force_login(self.user)

    def _authorize(self, **params):
        return self.client.get(
            "/o/authorize/",
            {
                "response_type": "code",
                "client_id": "shady-app",
                "scope": "openid email",
                "redirect_uri": "https://127.0.0.1/",
                "code_challenge": b64_encode(sha256(b"secret").digest()),
                "code_challenge_method": "S256",
                "state": "state",
            }
            | params,
        )

    def _page(self, response, frontend_path):
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, frontend_path)
        token = parse_qs(location.query)["token"][0]
        page = self.client.get(reverse("hidp_api:oidc_provider_page"), {"token": token})
        self.assertEqual(page.status_code, HTTPStatus.OK)
        return page.json()

    def test_consent(self):
        page = self._page(self._authorize(), "/frontend/consent/")

        self.assertEqual(page["page"], "consent")
        self.assertEqual(page["action"], "/o/authorize/")
        self.assertEqual(
            page["application"], {"name": "Shady App", "client_id": "shady-app"}
        )
        self.assertEqual(
            page["scopes"],
            [
                {"scope": "openid", "description": "OpenID Connect"},
                {"scope": "email", "description": "View email address"},
            ],
        )
        self.assertEqual(page["fields"]["client_id"], "shady-app")
        self.assertEqual(page["fields"]["state"], "state")
        self.assertNotIn("allow", page["fields"])

    def test_allow(self):
        page = self._page(self._authorize(), "/frontend/consent/")

        response = self.client.post(page["action"], page["fields"] | {"allow": True})

        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        self.assertRegex(
            response["Location"], r"^https://127\.0\.0\.1/\?code=[A-z0-9]+&state=state$"
        )

    def test_deny(self):
        page = self._page(self._authorize(), "/frontend/consent/")

        response = self.client.post(page["action"], page["fields"])

        self.assertEqual(
            response["Location"],
            "https://127.0.0.1/?error=access_denied&state=state",
        )

    def test_error_that_can_not_be_sent_to_the_application(self):
        page = self._page(self._authorize(client_id="unknown"), "/frontend/consent/")

        self.assertEqual(page["page"], "error")
        self.assertEqual(page["error"], "invalid_request")
        self.assertTrue(page["error_description"])

    def test_logout(self):
        response = self.client.get("/o/logout/")
        page = self._page(response, "/frontend/logout/")

        self.assertEqual(page["page"], "logout")
        self.assertEqual(page["action"], "/o/logout/")

        self.client.post(page["action"], page["fields"] | {"allow": True})

        self.assertNotIn("_auth_user_id", self.client.session)

    def test_expired_page(self):
        response = self.client.get(
            reverse("hidp_api:oidc_provider_page"), {"token": "invalid"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("token", response.json())


class TestHTMLPages(TestCase):
    """Without frontend URLs for them, the pages stay HTML."""

    def test_logout(self):
        self.client.force_login(user_factories.VerifiedUserFactory())

        response = self.client.get("/o/logout/")

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "hidp/accounts/logout_confirm.html")
