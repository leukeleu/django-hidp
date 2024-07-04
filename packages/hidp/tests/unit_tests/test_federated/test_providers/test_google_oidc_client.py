from django.test import SimpleTestCase

from hidp.federated.providers.google import GoogleOIDCClient


class TestGoogleOIDCClient(SimpleTestCase):
    def test_requires_client_secret(self):
        """The Google OIDC client requires a client secret."""
        with self.assertRaisesMessage(
            TypeError,
            "GoogleOIDCClient.__init__() missing 1 required"
            " keyword-only argument: 'client_secret'",
        ):
            GoogleOIDCClient(client_id="test")

    def test_initialize(self):
        """The Google OIDC client can be initialized."""
        client = GoogleOIDCClient(
            client_id="test",
            client_secret="secret",
            callback_base_url="https://example.com/",
        )
        self.assertEqual(client.client_id, "test")
        self.assertEqual(client.callback_base_url, "https://example.com/")
