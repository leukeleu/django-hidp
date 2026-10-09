from django.contrib.auth.backends import ModelBackend
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import TestCase, override_settings

from hidp.config import checks, configure_oidc_clients
from hidp.federated import flows
from hidp.federated.auth.backends import OIDCModelBackend
from hidp.federated.models import OpenIdConnection
from hidp.test.factories import user_factories

from .test_providers.example import ExampleOIDCClient

TOKEN_DATA = {
    "provider_key": "example",
    "claims": {"iss": "https://example.com", "sub": "example-subject", "groups": []},
    "user_info": {"groups": ["staff"], "locale": "nl"},
}


class ClaimsBackend(OIDCModelBackend):
    """A project backend that uses the claims, for instance to sync groups."""

    received_claims = None

    def authenticate(self, request=None, claims=None, **credentials):
        ClaimsBackend.received_claims = claims
        return super().authenticate(request, claims=claims, **credentials)


class OldSignatureBackend(OIDCModelBackend):
    """A project backend written before OIDC backends received the claims."""

    def authenticate(
        self, request=None, provider_key=None, issuer_claim=None, subject_claim=None
    ):
        return super().authenticate(
            request,
            provider_key=provider_key,
            issuer_claim=issuer_claim,
            subject_claim=subject_claim,
        )


class TestAuthenticate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()
        OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="https://example.com",
            subject_claim="example-subject",
        )

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="example"))
        ClaimsBackend.received_claims = None

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "django.contrib.auth.backends.ModelBackend",
            f"{__name__}.ClaimsBackend",
        ]
    )
    def test_backend_receives_the_claims(self):
        self.assertEqual(flows.authenticate(None, TOKEN_DATA), self.user)
        # The claims of the ID token, completed with the user info.
        self.assertEqual(
            ClaimsBackend.received_claims,
            {
                "iss": "https://example.com",
                "sub": "example-subject",
                "groups": [],
                "locale": "nl",
            },
        )
        self.assertEqual(checks.check_oidc_backends_accept_claims(), [])

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "django.contrib.auth.backends.ModelBackend",
            f"{__name__}.OldSignatureBackend",
        ]
    )
    def test_backend_without_claims_still_authenticates(self):
        self.assertEqual(flows.authenticate(None, TOKEN_DATA), self.user)
        self.assertEqual(checks.check_oidc_backends_accept_claims(), [checks.W002])

    def test_other_backends_are_not_checked(self):
        self.assertFalse(issubclass(ModelBackend, OIDCModelBackend))
        self.assertEqual(flows.authenticate(None, TOKEN_DATA), self.user)


class TestTokenData(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="example"))
        self.request = HttpRequest()
        self.request.session = SessionStore()

    def _store(self):
        return flows.store_token_data(
            self.request,
            flows.login_token_generator,
            provider_key="example",
            claims=TOKEN_DATA["claims"],
            user_info=TOKEN_DATA["user_info"],
        )

    def test_round_trip(self):
        token = self._store()

        self.assertEqual(
            flows.get_token_data(
                self.request, token, token_generator=flows.login_token_generator
            ),
            TOKEN_DATA,
        )

    def test_token_of_another_step(self):
        token = self._store()

        self.assertIsNone(
            flows.get_token_data(
                self.request, token, token_generator=flows.link_token_generator
            )
        )

    def test_unregistered_provider(self):
        token = self._store()
        configure_oidc_clients()

        self.assertIsNone(
            flows.get_token_data(
                self.request, token, token_generator=flows.login_token_generator
            )
        )

    def test_discard(self):
        token = self._store()

        flows.discard_token_data(self.request, token)

        self.assertIsNone(
            flows.get_token_data(
                self.request, token, token_generator=flows.login_token_generator
            )
        )


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "hidp.federated.auth.backends.OIDCModelBackend",
        f"{__name__}.ClaimsBackend",
    ]
)
class TestIsOIDCSession(TestCase):
    def _request(self, backend):
        request = HttpRequest()
        request.session = SessionStore()
        if backend:
            request.session["_auth_user_backend"] = backend
        return request

    def test_oidc_backend(self):
        for backend in (
            "hidp.federated.auth.backends.OIDCModelBackend",
            f"{__name__}.ClaimsBackend",
        ):
            with self.subTest(backend=backend):
                self.assertTrue(flows.is_oidc_session(self._request(backend)))

    def test_other_backends(self):
        for backend in (
            None,
            "django.contrib.auth.backends.ModelBackend",
            # No longer configured.
            f"{__name__}.OldSignatureBackend",
        ):
            with self.subTest(backend=backend):
                self.assertFalse(flows.is_oidc_session(self._request(backend)))
