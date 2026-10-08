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

    def test_single_tenant(self):
        """A single-tenant application uses the endpoints of its tenant."""
        client = MicrosoftOIDCClient(client_id="test", tenant_id="contoso.com")

        base_url = "https://login.microsoftonline.com/contoso.com"
        self.assertEqual(
            client.authorization_endpoint, f"{base_url}/oauth2/v2.0/authorize"
        )
        self.assertEqual(client.token_endpoint, f"{base_url}/oauth2/v2.0/token")
        self.assertEqual(client.jwks_uri, f"{base_url}/discovery/v2.0/keys")
        self.assertEqual(client.get_issuer(claims={"tid": "other"}), f"{base_url}/v2.0")
        # Other instances keep the /common/ endpoints.
        self.assertIn("/common/", MicrosoftOIDCClient(client_id="test").token_endpoint)

    def test_invalid_tenant(self):
        for tenant_id in ("", "contoso.com/evil"):
            with self.subTest(tenant_id=tenant_id), self.assertRaises(ValueError):
                MicrosoftOIDCClient(client_id="test", tenant_id=tenant_id)
