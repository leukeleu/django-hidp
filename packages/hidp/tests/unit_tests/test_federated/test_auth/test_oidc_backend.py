from django.test import TestCase, modify_settings

from hidp.accounts.auth import authenticate
from hidp.config import configure_oidc_clients
from hidp.federated.models import OpenIdConnection
from hidp.test.factories import user_factories

from ..test_providers.example import ExampleOIDCClient


@modify_settings(
    AUTHENTICATION_BACKENDS={"append": "hidp.federated.auth.backends.OIDCModelBackend"}
)
class TestOIDCModelBackend(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.oidc_connection = OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="https://example.com",
            subject_claim="example-subject",
        )
        # Assume the provider was in use at some point, but is now unregistered
        cls.unregistered_connection = OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="unregistered",
            issuer_claim="https://example.com/other",
            subject_claim="other-subject",
        )

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="example"))

    def test_missing_parameters(self):
        """Skip authentication if any of the required parameters is missing."""
        self.assertIsNone(
            authenticate(
                request=None, provider_key="example", subject_claim="example-subject"
            )
        )

    def test_unregistered_provider(self):
        """Return None if the provider is not registered (anymore), querying once."""
        with self.assertNumQueries(1):
            self.assertIsNone(
                authenticate(
                    request=None,
                    provider_key="unregistered",
                    issuer_claim="https://example.com/other",
                    subject_claim="other-subject",
                )
            )

    def test_invalid_credentials(self):
        """Return None if the credentials are invalid."""
        with self.assertNumQueries(1):
            self.assertIsNone(
                authenticate(
                    request=None,
                    provider_key="example",
                    issuer_claim="https://example.com",
                    subject_claim="invalid-subject",
                )
            )

    def test_success(self):
        """Return the user associated with the OpenID connection in one query."""
        with self.assertNumQueries(1):
            self.assertEqual(
                self.user,
                authenticate(
                    request=None,
                    provider_key="example",
                    issuer_claim="https://example.com",
                    subject_claim="example-subject",
                ),
            )
