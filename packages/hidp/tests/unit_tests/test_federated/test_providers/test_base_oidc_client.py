from django.test import SimpleTestCase

from hidp.federated.providers.base import OIDCClient

from .example import ExampleOIDCClient


class UnfinishedOIDCClient(OIDCClient):
    # Missing all the required attributes
    ...


class UnsafeOIDCClient(OIDCClient):
    # A seemingly valid OIDC client, but the endpoints do not utilize TLS.
    provider_key = "unsafe"
    issuer = "http://example.com"
    authorization_endpoint = "http://example.com/auth"
    token_endpoint = "http://example.com/token"
    userinfo_endpoint = "http://example.com/userinfo"
    jwks_uri = "http://example.com/jwks"


class BadIdentifierOIDCClient(ExampleOIDCClient):
    # A valid OIDC client, but with a provider key that is not URL-safe.
    provider_key = "Bad Identifier (test)"


class NamedExampleOIDCClient(ExampleOIDCClient):
    # A valid OIDC client, but with a custom name.
    name = "Named Example"


class NoPKCEOIDCClient(ExampleOIDCClient):
    # A valid OIDC client, but lacking PKCE support.
    has_pkce_support = False


class TestCustomProvider(SimpleTestCase):
    def test_invalid_provider(self):
        """Missing attributes raise a NotImplementedError."""
        with self.assertRaisesMessage(
            NotImplementedError,
            "'UnfinishedOIDCClient' misses (some of) the required attributes.",
        ):
            UnfinishedOIDCClient(client_id="test")

    def test_unsafe_endpoints(self):
        """An OIDC client with unsafe endpoints raises a ValueError."""
        with self.assertRaisesMessage(
            ValueError,
            "All endpoints must use TLS (https): 'http://example.com/auth' does not.",
        ):
            UnsafeOIDCClient(client_id="test")

    def test_bad_identifier(self):
        """A provider key that is not URL-safe raises a ValueError."""
        with self.assertRaisesMessage(
            ValueError,
            "'BadIdentifierOIDCClient.provider_key' is not URL-safe:"
            " 'Bad Identifier (test)'",
        ):
            BadIdentifierOIDCClient(client_id="test")

    def test_invalid_callback_base_url(self):
        """An invalid callback base URL raises a ValueError."""
        with self.assertRaisesMessage(
            ValueError,
            "Invalid callback base url: 'localhost:8000/example'."
            " Should be in the form of 'https://<netloc>'"
            " (path, querystring and/or fragment are not allowed).",
        ):
            ExampleOIDCClient(
                client_id="test",
                callback_base_url="localhost:8000/example",
            )

    def test_insecure_callback_base_url(self):
        """An insecure callback base URL raises a ValueError."""
        with self.assertRaisesMessage(
            ValueError,
            "Invalid callback base url: 'http://example.com/'."
            " Should be in the form of 'https://<netloc>'"
            " (path, querystring and/or fragment are not allowed).",
        ):
            ExampleOIDCClient(
                client_id="test",
                callback_base_url="http://example.com/",
            )

    def test_valid_callback_base_url(self):
        """A valid callback_base_url is stored."""
        client = ExampleOIDCClient(
            client_id="test", callback_base_url="https://example.com/"
        )
        self.assertEqual(client.client_id, "test")
        self.assertEqual(client.callback_base_url, "https://example.com/")

    def test_client_with_secret(self):
        """A client with a secret is stored."""
        client = ExampleOIDCClient(client_id="test", client_secret="secret")
        self.assertEqual(client.client_id, "test")
        self.assertEqual(client.client_secret, "secret")

    def test_client_without_pkce_requires_secret(self):
        """A client without PKCE support requires a client secret."""
        with self.assertRaisesMessage(
            ValueError,
            (
                "Please provide a client secret."
                " 'NoPKCEOIDCClient' declares it does not support PKCE,"
                " which means a client secret must be required for token exchange."
            ),
        ):
            NoPKCEOIDCClient(client_id="test")

    def test_minimal_client(self):
        """client_secret and callback_base_url default to None if not provided."""
        client = ExampleOIDCClient(client_id="test")
        self.assertEqual(client.client_id, "test")
        self.assertEqual(client.name, "Example")
        self.assertEqual(client.client_secret, None)
        self.assertEqual(client.callback_base_url, None)

    def test_get_issuer(self):
        """The issuer is returned by get_issuer."""
        client = ExampleOIDCClient(client_id="test")
        self.assertEqual(client.issuer, client.get_issuer(claims={}))

    def test_named_client(self):
        """Custom name takes precedence over the default name."""
        client = NamedExampleOIDCClient(client_id="test")
        self.assertEqual(client.name, "Named Example")
