from django.db import IntegrityError
from django.test import TestCase

from hidp.federated import models
from hidp.test.factories import user_factories


class TestOpenIdConnectionModel(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.oidc_data = models.OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="test-provider",
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
                provider_key="test-provider",
                issuer_claim="test-issuer",
                subject_claim="test-subject",
            )

    def test_str(self):
        self.assertEqual(
            str(self.oidc_data),
            (
                f"user: '{self.user.id}'"
                f" provider: 'test-provider'"
                f" iss: 'test-issuer'"
                f" sub: 'test-subject'"
            ),
        )
