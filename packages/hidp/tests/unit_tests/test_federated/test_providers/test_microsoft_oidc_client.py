from django.test import SimpleTestCase

from hidp.federated.providers.microsoft import MicrosoftOIDCClient


class TestMicrosoftOIDCClient(SimpleTestCase):
    def test_initialize(self):
        """The Microsoft OIDC client can be initialized."""
        client = MicrosoftOIDCClient(
            client_id="test",
        )
        self.assertEqual(client.client_id, "test")
        self.assertEqual(client.callback_base_url, None)

    def test_get_issuer(self):
        """The issuer URL is formatted with the tenant ID."""
        client = MicrosoftOIDCClient(client_id="test")
        issuer = client.get_issuer(claims={"tid": "example"})
        self.assertEqual(issuer, "https://login.microsoftonline.com/example/v2.0")

        with self.subTest("Missing tenant ID"):
            # Returns the unformatted issuer URL if the tenant ID is missing.
            issuer = client.get_issuer(claims={})
            self.assertEqual(issuer, client.issuer)
