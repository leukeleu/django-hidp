from unittest import mock

import requests

from jwcrypto.jwk import JWK, JWKSet

from django.core.cache import cache
from django.test import TestCase, override_settings

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
        """
        Raise KeyError when the client is not the same instance
        as the registered client.
        """
        with self.assertRaisesMessage(
            KeyError, "Client is not registered for 'example'."
        ):
            jwks.get_oidc_client_jwks(ExampleOIDCClient(client_id="test"))

    @mock.patch.object(jwks.requests, "get")
    def test_reluctantly_fetches_jwks_on_cache_miss(self, mock_get):
        """
        Fetch the JWKS data from the OIDC provider when the data is missing
        from the cache.
        """
        # Just raise an exception to stop the function early.
        # This test doubles as a test for request failure.
        mock_get.side_effect = [requests.RequestException("error")]
        with self.assertLogs(logger=jwks.logger, level="WARNING") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        # Complains about having to fetch JWKS data
        self.assertEqual(
            logs.records[0].getMessage(),
            "JWK data for 'example' is not cached,"
            " reluctantly fetching from 'https://example.com/jwks'.",
        )

        # Fetches JWKS data from the OIDC provider
        mock_get.assert_called_once_with(
            self.oidc_client.jwks_uri,
            headers={"Accept": "application/json"},
            timeout=(5, 30),
        )

        # Logs the failure to fetch JWKS data
        self.assertEqual(
            logs.records[1].getMessage(),
            "Failed to fetch JWK data for 'example' from 'https://example.com/jwks'.",
        )

        # Return None after failing to fetch JWKS data
        self.assertIsNone(jwks_data, "Expected None after failing to fetch JWKS data.")

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch JWKS data.",
                )
            mock_get.assert_called_once()  # No new requests are made

    @mock.patch.object(jwks.requests, "get")
    def test_handles_error_response(self, mock_get):
        """
        Log an exception when the JWKS endpoint returns an error response.
        """
        mock_get.return_value = _mock_response(b"Not Found", status_code=404)

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            # This also triggers the cache miss warning, but it's not checked here,
            # as the previous test already covers that.
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        mock_get.assert_called()  # The request is made

        self.assertIsNone(jwks_data, "Expected None after failing to fetch JWKS data.")
        self.assertEqual(
            logs.records[0].getMessage(),
            "Error after fetching JWK data for 'example'"
            " from 'https://example.com/jwks': 404.",
        )

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch JWKS data.",
                )
            mock_get.assert_called_once()  # No new requests are made

    @mock.patch.object(jwks.requests, "get")
    def tests_handles_invalid_response(self, mock_get):
        """
        Log an exception when the JWKS endpoint returns an invalid response.
        """
        mock_get.return_value = _mock_response(
            b"This is not JSON, you must be mistaken."
        )

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        self.assertIsNone(jwks_data, "Expected None after failing to fetch JWKS data.")
        self.assertEqual(
            logs.records[0].getMessage(),
            "Failed to decode JWK data for 'example' from 'https://example.com/jwks'.",
        )

        with self.subTest("Failure is cached"):
            # The second call doesn't try to fetch the data again.
            with self.assertNoLogs():
                self.assertIsNone(
                    jwks.get_oidc_client_jwks(self.oidc_client),
                    "Expected None after failing to fetch JWKS data.",
                )
            mock_get.assert_called_once()

    @mock.patch.object(jwks.requests, "get")
    def test_valid_response(self, mock_get):
        """
        Return the JWKS data when the JWKS endpoint returns a valid response.
        """
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
        """
        Log an exception when the cache contains an invalid value.
        """
        mock_cache_get.return_value = b"This is not JSON, you must be mistaken."
        mock_requests_get.return_value = _mock_response(self.key_set.encode())

        with self.assertLogs(logger=jwks.logger, level="ERROR") as logs:
            jwks_data = jwks.get_oidc_client_jwks(self.oidc_client)

        self.assertEqual(
            logs.records[0].getMessage(),
            "Failed to decode JWK data for 'example' from cache.",
        )

        # Falls back to fetching the data from the provider.
        mock_requests_get.assert_called_once()  # The request is made
        self.assertIsInstance(jwks_data, JWKSet)
