from ..federated.providers.base import OIDCClient

_registry = {}


def configure_oidc_clients(*clients):
    """
    Configure OIDC clients for the HIdP application.

    Note:
    This function should be called **once** in the application configuration.
    Subsequent calls will overwrite the registered clients.

    Arguments:
        *clients (OIDCClient):
            One or more OIDCClient instances to register.
    """
    _registry.clear()
    for client in clients:
        if not isinstance(client, OIDCClient):
            raise TypeError(f"Expected OIDCClient, got {type(client).__name__!r}")
        if client.provider_key in _registry:
            raise ValueError(f"Duplicate provider key: {client.provider_key!r}")
        else:
            _registry[client.provider_key] = client


def get_oidc_client(provider_key):
    """
    Retrieve an OIDC client by provider key.

    Arguments:
        provider_key (str):
            The provider key of the client to retrieve.

    Returns:
        OIDCClient:
            The OIDC client instance.

    Raises:
        KeyError:
            If the provider key is not registered.
    """
    try:
        return _registry[provider_key]
    except KeyError:
        raise KeyError(
            f"No OIDC client registered for provider key: {provider_key!r}"
        ) from None
