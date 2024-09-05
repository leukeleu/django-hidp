import io

from unittest import mock

import requests

from jwcrypto.jwk import JWK, JWKSet

from django.core.cache import cache
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings

from hidp import config
from hidp.federated.oidc import jwks

from ..test_providers.example import ExampleOIDCClient


def _mock_response(content, *, status_code=200):
    response = requests.Response()
    response._content = content  # noqa: SLF001 (protected attribute)
    response.status_code = status_code
    return response


@override_settings(
    CACHES={
        "default": {
            # The module relies on caching to behave correctly.
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    },
)
class TestJwksStore(TestCase):
    @classmethod
    def setUpTestData(cls):
        key = JWK(generate="RSA")
        key_set = JWKSet()
        key_set.add(key)
        cls.key_set = key_set.export(private_keys=False)

    def setUp(self):
        self.oidc_client = ExampleOIDCClient(client_id="test")
        config.configure_oidc_clients(self.oidc_client)
        cache.clear()

    def test_get_jwks_for_unregistered_client(self):
        """If the client is not registered, raise a KeyError."""
        with self.assertRaisesMessage(
            KeyError, "Client is not registered for 'example'."
        ):
            jwks.get_oidc_client_jwks(ExampleOIDCClient(client_id="test"))

    @mock.patch.object(jwks.requests, "get")
    def test_reluctantly_fetches_jwks_on_cache_miss(self, mock_get):
        """If signing keys are not cached, fetch them from the OIDC provider."""
        # Just raise an exception to stop the function early.
        # This test doubles as a test for request failure.
        mock_get.side_effect = [requests.RequestException("error")]
        with self.assertLogs(logger=jwks.logger, level="WARNING") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        # Complains about having to fetch signing keys
        self.assertEqual(
            logs.records[0].getMessage(),
            "Signing keys for 'example' are not cached,"
            " reluctantly fetching from 'https://example.com/jwks'.",
        )

        # Fetches signing keys from the OIDC provider
        mock_get.assert_called_once_with(
            self.oidc_client.jwks_uri,
            headers={"Accept": "application/json"},
            timeout=(5, 30),
        )

        # Logs the failure to fetch signing keys
        self.assertEqual(
            logs.records[1].getMessage(),
            "Failed to fetch signing keys for 'example' from 'https://example.com/jwks'.",
        )

        # Return None after failing to fetch signing keys
        self.assertIsNone(
            jwks_data, "Expected None after failing to fetch signing keys."
        )

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch signing keys.",
                )
            mock_get.assert_called_once()  # No new requests are made

    @mock.patch.object(jwks.requests, "get")
    def test_handles_error_response(self, mock_get):
        """Log an exception when the JWKS endpoint returns an error response."""
        mock_get.return_value = _mock_response(b"Not Found", status_code=404)

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            # This also triggers the cache miss warning, but it's not checked here,
            # as the previous test already covers that.
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        mock_get.assert_called()  # The request is made

        self.assertIsNone(
            jwks_data, "Expected None after failing to fetch signing keys."
        )
        self.assertEqual(
            logs.records[0].getMessage(),
            "Error after fetching signing keys for 'example'"
            " from 'https://example.com/jwks': 404.",
        )

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch signing keys.",
                )
            mock_get.assert_called_once()  # No new requests are made

    @mock.patch.object(jwks.requests, "get")
    def tests_handles_invalid_response(self, mock_get):
        """Log an exception when the JWKS endpoint returns an invalid response."""
        mock_get.return_value = _mock_response(
            b"This is not JSON, you must be mistaken."
        )

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        self.assertIsNone(
            jwks_data, "Expected None after failing to fetch signing keys."
        )
        self.assertEqual(
            logs.records[0].getMessage(),
            "Failed to decode signing keys for 'example' from 'https://example.com/jwks'.",
        )

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch signing keys.",
                )
            mock_get.assert_called_once()

    @mock.patch.object(jwks.requests, "get")
    def test_valid_response(self, mock_get):
        """Return the signing keys when the JWKS endpoint returns a valid response."""
        # This test doubles as a test for successful request caching,
        # and also tests eager fetching.
        mock_get.return_value = _mock_response(self.key_set.encode())

        jwk_data = jwks.get_oidc_client_jwks(self.oidc_client)

        mock_get.assert_called_once()  # The request is made
        self.assertIsInstance(jwk_data, JWKSet)

        with self.subTest("Success is cached"):
            # The second call doesn't try to fetch the data again.
            self.assertEqual(jwk_data, jwks.get_oidc_client_jwks(self.oidc_client))
            mock_get.assert_called_once()  # No new requests are made

        with self.subTest("Cache is bypassed"):
            # Cache is ignored, so two requests are made.
            self.assertEqual(
                jwk_data, jwks.get_oidc_client_jwks(self.oidc_client, eager=True)
            )
            self.assertEqual(
                len(mock_get.mock_calls), 2, "Expected two requests to be made."
            )

    @mock.patch.object(jwks.requests, "get")
    @mock.patch.object(jwks.cache, "get")
    def test_invalid_cache_value(self, mock_cache_get, mock_requests_get):
        """Log an exception when the cache contains an invalid value."""
        mock_cache_get.return_value = b"This is not JSON, you must be mistaken."
        mock_requests_get.return_value = _mock_response(self.key_set.encode())

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        self.assertEqual(
            logs.records[0].getMessage(),
            "Failed to decode signing keys for 'example' from cache.",
        )

        # Falls back to fetching the data from the provider.
        mock_requests_get.assert_called_once()  # The request is made
        self.assertIsInstance(jwks_data, JWKSet)


@mock.patch.object(jwks, "get_oidc_client_jwks", autospec=True)
class RefreshJwks(SimpleTestCase):
    def setUp(self):
        class AnotherOIDCClient(ExampleOIDCClient):
            provider_key = "another"

        self.oidc_clients = [
            ExampleOIDCClient(client_id="test"),
            AnotherOIDCClient(client_id="another"),
        ]
        config.configure_oidc_clients(*self.oidc_clients)

    def test_refresh_registered_oidc_clients_jwks(self, mock_get_oidc_client_jwks):
        """Eagerly fetches the signing keys for all registered OIDC clients."""
        jwks.refresh_registered_oidc_clients_jwks()
        mock_get_oidc_client_jwks.assert_has_calls(
            [mock.call(client, eager=True) for client in self.oidc_clients]
        )

    def test_refresh_oidc_clients_jwks_management_command(
        self, mock_get_oidc_client_jwks
    ):
        """Eagerly fetches the signing keys and logs the process to stdout."""
        stdout = io.StringIO()
        call_command("refresh_oidc_clients_jwks", stdout=stdout)
        mock_get_oidc_client_jwks.assert_has_calls(
            [mock.call(client, eager=True) for client in self.oidc_clients]
        )
        self.assertEqual(
            [
                f"Fetching signing keys for '{client.provider_key}'"
                f" from '{client.jwks_uri}'..."
                for client in self.oidc_clients
            ],
            stdout.getvalue().splitlines(),
        )
