from django.db import IntegrityError
from django.test import TestCase

from hidp.config import oidc_clients
from hidp.federated import models
from hidp.test.factories import user_factories

from .test_providers.example import ExampleOIDCClient


class TestOpenIdConnectionModel(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.connection = models.OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="test-issuer",
            subject_claim="test-subject",
        )

    def test_unique_together(self):
        with self.assertRaisesMessage(
            IntegrityError, "duplicate key value violates unique constraint"
        ):
            models.OpenIdConnection.objects.create(
                # Different user, but same OIDC data
                user=user_factories.UserFactory(),
                provider_key="example",
                issuer_claim="test-issuer",
                subject_claim="test-subject",
            )

    def test_str(self):
        oidc_clients.configure_oidc_clients(ExampleOIDCClient(client_id="test"))
        with self.subTest("Registered provider"):
            self.assertEqual(
                str(self.connection),
                "Example (test-subject)",
            )

        oidc_clients.configure_oidc_clients()
        with self.subTest("Unregistered provider"):
            self.assertEqual(
                str(self.connection),
                "Unknown provider: example (test-subject)",
            )

    def test_get_by_provider_and_claims(self):
        with self.assertNumQueries(1):
            connection = models.OpenIdConnection.objects.get_by_provider_and_claims(
                provider_key="example",
                issuer_claim="test-issuer",
                subject_claim="test-subject",
            )
            self.assertEqual(connection, self.connection)
            self.assertEqual(connection.user, self.user)
