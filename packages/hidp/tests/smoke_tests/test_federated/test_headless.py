from http import HTTPStatus
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.urls import reverse

from hidp.config import checks, configure_oidc_clients
from hidp.federated import flows, models
from hidp.federated.oidc.exceptions import InvalidOIDCStateError
from hidp.test.factories import user_factories

from ...unit_tests.test_federated.test_providers.example import ExampleOIDCClient
from .test_views import _VALID_AUTH_CALLBACK

UserModel = get_user_model()

HEADLESS_FRONTEND_URLS = settings.HIDP_FRONTEND_URLS | {
    "login": "/frontend/login/",
    "oidc_registration": "/frontend/register/",
    "oidc_link": "/frontend/link/",
    "email_verification_required": "/frontend/verify/",
}

CALLBACK = "hidp.federated.views.authorization_code_flow.handle_authentication_callback"


# Only the URLs a headless project mounts: the HTML pages can not be reversed.
HEADLESS_URLCONF = "tests.smoke_tests.test_federated.headless_urls"


@override_settings(
    HIDP_FRONTEND_URLS=HEADLESS_FRONTEND_URLS,
    REGISTRATION_ENABLED=True,
    ROOT_URLCONF=HEADLESS_URLCONF,
)
class TestHeadlessCallback(TestCase):
    """The callback hands every step but the login itself to the frontend."""

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))
        self.url = reverse(
            "hidp_oidc_client:callback", kwargs={"provider_key": "example"}
        )

    def _callback(self, next_url="/next/"):
        with mock.patch(CALLBACK, return_value=(*_VALID_AUTH_CALLBACK, next_url)):
            return self.client.get(self.url, secure=True)

    def test_registration(self):
        response = self._callback()

        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        self.assertRegex(
            response.url,
            r"^https://testserver/frontend/register/\?token=[^&]+&next=%2Fnext%2F$",
        )

    @override_settings(REGISTRATION_ENABLED=False)
    def test_registration_disabled(self):
        response = self._callback()

        self.assertEqual(
            response.url,
            "https://testserver/frontend/login/?oidc_error=registration_disabled",
        )

    def test_link(self):
        self.client.force_login(user_factories.VerifiedUserFactory())

        response = self._callback()

        self.assertRegex(
            response.url,
            r"^https://testserver/frontend/link/\?token=[^&]+&next=%2Fnext%2F$",
        )

    def test_account_exists(self):
        user_factories.VerifiedUserFactory(email="user@example.com")

        response = self._callback()

        self.assertEqual(
            response.url,
            "https://testserver/frontend/login/?oidc_error=account_exists&next=%2Fnext%2F",
        )

    def test_login_stays_in_django(self):
        models.OpenIdConnection.objects.create(
            user=user_factories.VerifiedUserFactory(),
            provider_key="example",
            issuer_claim="example",
            subject_claim="test_subject",
        )

        response = self._callback()

        self.assertTrue(response.url.startswith(reverse("hidp_oidc_client:login")))

    def test_expired_request(self):
        with mock.patch(CALLBACK, side_effect=InvalidOIDCStateError("expired")):
            response = self.client.get(self.url, secure=True)

        self.assertEqual(
            response.url,
            "https://testserver/frontend/login/?oidc_error=request_expired",
        )


@override_settings(
    HIDP_FRONTEND_URLS=HEADLESS_FRONTEND_URLS, ROOT_URLCONF=HEADLESS_URLCONF
)
class TestHeadlessLogin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_oidc_client:login")
        cls.user = user_factories.UserFactory()
        models.OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def _token(self):
        session = self.client.session
        request = HttpRequest()
        request.session = session
        token = flows.store_token_data(
            request,
            flows.login_token_generator,
            provider_key="example",
            claims={"iss": "example", "sub": "test-subject", "email": "u@example.com"},
            user_info={},
        )
        session.save()
        return token

    def test_unverified_user_verifies_through_the_frontend(self):
        response = self.client.get(self.url, {"token": self._token(), "next": "/n/"})

        self.assertEqual(
            response.url, "http://testserver/frontend/verify/?next=%2Fn%2F"
        )
        self.assertRegex(
            mail.outbox[0].body,
            r"http://testserver/frontend/verify/\S+/\?next=%2Fn%2F",
        )
        session_state = self.client.get(reverse("hidp_api:session")).json()
        self.assertEqual(session_state["pending"], [{"step": "email_verify"}])

    def test_invalid_token(self):
        response = self.client.get(self.url, {"token": "invalid"})

        self.assertEqual(
            response.url, "http://testserver/frontend/login/?oidc_error=invalid_token"
        )

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save()

        response = self.client.get(self.url, {"token": self._token()})

        self.assertEqual(
            response.url,
            "http://testserver/frontend/login/?oidc_error=invalid_credentials",
        )


@override_settings(HIDP_FRONTEND_URLS=HEADLESS_FRONTEND_URLS)
class TestHeadlessHtmlPages(TestCase):
    """Old links to the HTML pages of registering and linking go to the frontend."""

    def test_registration(self):
        response = self.client.get(
            reverse("hidp_oidc_client:register"), {"token": "abc", "next": "/n/"}
        )

        self.assertEqual(
            response.url, "http://testserver/frontend/register/?token=abc&next=%2Fn%2F"
        )

    def test_link(self):
        self.client.force_login(user_factories.VerifiedUserFactory())

        response = self.client.get(
            reverse("hidp_oidc_management:link_account"), {"token": "abc"}
        )

        self.assertEqual(response.url, "http://testserver/frontend/link/?token=abc")


class TestOIDCFrontendUrlsCheck(TestCase):
    def test_none(self):
        self.assertEqual(checks.check_oidc_frontend_urls(), [])

    @override_settings(HIDP_FRONTEND_URLS=HEADLESS_FRONTEND_URLS)
    def test_all(self):
        self.assertEqual(checks.check_oidc_frontend_urls(), [])

    @override_settings(
        HIDP_FRONTEND_URLS=settings.HIDP_FRONTEND_URLS | {"login": "/frontend/login/"}
    )
    def test_some(self):
        self.assertEqual(checks.check_oidc_frontend_urls(), [checks.E015])


class TestOIDCCallbackUrlCheck(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    @override_settings(ROOT_URLCONF=HEADLESS_URLCONF)
    def test_mounted(self):
        self.assertEqual(checks.check_oidc_callback_url(), [])

    @override_settings(ROOT_URLCONF="tests.unit_tests.test_config.headless_urls")
    def test_not_mounted(self):
        self.assertEqual(checks.check_oidc_callback_url(), [checks.E017])

    @override_settings(ROOT_URLCONF="tests.unit_tests.test_config.headless_urls")
    def test_no_providers(self):
        configure_oidc_clients()

        self.assertEqual(checks.check_oidc_callback_url(), [])
