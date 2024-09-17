import contextlib

from ..federated.oidc import jwks
from ..federated.providers.base import OIDCClient

_registry = {}


def configure_oidc_clients(*clients, eagerly_provision_jwk_store=False):
    """
    Configure OIDC clients for the HIdP application.

    Note:
    This function should be called **once** in the application configuration.
    Subsequent calls will overwrite the registered clients.

    Arguments:
        *clients (OIDCClient):
            One or more OIDCClient instances to register.
        eagerly_provision_jwk_store (bool):
            Whether to eagerly load the signing keys for the registered clients.
            This is useful to ensure that the keys are loaded at application startup
            instead of the first time they are needed.

    """
    _registry.clear()
    for client in clients:
        if not isinstance(client, OIDCClient):
            raise TypeError(f"Expected OIDCClient, got {type(client).__name__!r}")
        if client.provider_key in _registry:
            raise ValueError(f"Duplicate provider key: {client.provider_key!r}")
        else:
            _registry[client.provider_key] = client

    # Finished registering clients, provision JWK store if requested.
    if eagerly_provision_jwk_store:
        for client in clients:
            jwks.get_oidc_client_jwks(client, eager=True)


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


def get_oidc_client_or_none(provider_key):
    """
    Retrieve an OIDC client by provider key or None if provider can not be found.

    Arguments:
        provider_key (str):
            The provider key of the client to retrieve.

    Returns:
        OIDCClient | None:
            The OIDC client instance or None.
    """
    with contextlib.suppress(KeyError):
        return get_oidc_client(provider_key) if provider_key else None
    return None


def get_registered_oidc_clients():
    """
    Retrieve a list of registered OIDC clients.

    Returns:
        list of OIDCClient:
            A list of OIDC client instances.
    """
    return list(_registry.values())
