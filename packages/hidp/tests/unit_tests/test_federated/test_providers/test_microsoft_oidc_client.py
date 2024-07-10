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
