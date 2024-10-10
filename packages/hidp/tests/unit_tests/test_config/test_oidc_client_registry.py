from django.test import SimpleTestCase

from hidp.config import configure_oidc_clients
from hidp.config.oidc_clients import (
    get_oidc_client,
    get_oidc_client_or_none,
    get_registered_oidc_clients,
)

from ..test_federated.test_providers.example import ExampleOIDCClient


class ExampleOIDCClient2(ExampleOIDCClient):
    # Same as the ExampleOIDCClient, but with a different provider key.
    provider_key = "example-2"


class TestOIDCClientsRegistry(SimpleTestCase):
    def setUp(self):
        # Empty the registry before each test, by configuring zero clients.
        configure_oidc_clients()

    def test_register_client(self):
        """Registering a client makes it retrievable."""
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))
        client = get_oidc_client("example")
        self.assertIsInstance(client, ExampleOIDCClient)

    def test_register_duplicate_client(self):
        """Registering a client with a duplicate provider key raises an error."""
        with self.assertRaisesMessage(
            ValueError,
            "Duplicate provider key: 'example'",
        ):
            configure_oidc_clients(
                ExampleOIDCClient(client_id="test"),
                ExampleOIDCClient(client_id="test-2"),
            )

    def test_register_multiple_clients(self):
        """Registering multiple clients makes them all retrievable."""
        configure_oidc_clients(
            ExampleOIDCClient(client_id="test"),
            ExampleOIDCClient2(client_id="test-2"),
        )
        client = get_oidc_client("example")
        self.assertIsInstance(client, ExampleOIDCClient)
        client = get_oidc_client("example-2")
        self.assertIsInstance(client, ExampleOIDCClient2)

    def test_register_invalid_client(self):
        """Registering anything other than an OIDCClient raises a TypeError."""
        with self.assertRaisesMessage(
            TypeError,
            "Expected OIDCClient, got 'str'",
        ):
            configure_oidc_clients("not a client")

    def test_register_twice(self):
        """Registering clients twice overwrites the previous registration."""
        configure_oidc_clients(
            ExampleOIDCClient(client_id="test"),
            ExampleOIDCClient2(client_id="test-2"),
        )
        configure_oidc_clients(ExampleOIDCClient(client_id="test-2"))
        client = get_oidc_client("example")
        # The second registration overwrites the first one
        self.assertIsInstance(client, ExampleOIDCClient)
        self.assertEqual(client.client_id, "test-2")

    def test_get_unregistered_client(self):
        """Retrieving an unregistered client raises a KeyError."""
        with self.assertRaisesMessage(
            KeyError,
            "No OIDC client registered for provider key: 'example'",
        ):
            get_oidc_client("example")

    def test_get_registered_oidc_clients(self):
        """Retrieving all registered clients returns a list in registration order."""
        clients = [
            ExampleOIDCClient(client_id="test"),
            ExampleOIDCClient2(client_id="test-2"),
        ]
        configure_oidc_clients(*clients)
        registered_clients = get_registered_oidc_clients()
        self.assertEqual(len(clients), len(registered_clients))
        self.assertEqual(clients, registered_clients)

        with self.subTest("Mutation"):
            # Mutating the returned list should not affect the registry.
            registered_clients[0] = None
            self.assertEqual(clients, get_registered_oidc_clients())

    def test_get_oidc_client_or_none(self):
        """Retrieving a client or None should return the client or None."""
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

        with self.subTest("Registered client"):
            client = get_oidc_client_or_none("example")
            self.assertIsInstance(client, ExampleOIDCClient)

        with self.subTest("Unknown client"):
            client = get_oidc_client_or_none("non-existent")
            self.assertIsNone(client)

        with self.subTest("None key"):
            client = get_oidc_client_or_none(None)
            self.assertIsNone(client)
