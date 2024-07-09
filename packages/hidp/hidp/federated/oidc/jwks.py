import logging

from datetime import timedelta

import requests

from jwcrypto import jwk

from django.core.cache import cache

from ...config import oidc_clients

_JWKS_CACHE_KEY_PREFIX = "hidp:oidc_client_jwks"
# Keys should rarely change. Keep this timeout high to avoid unnecessary requests
# to the JWKS endpoint during normal operation.
# Keys can be fetched eagerly (and periodically) if freshness is a concern.
_JWKS_DATA_CACHE_TIMEOUT = timedelta(days=7).total_seconds()
# If an error occurs while fetching the JWKS data, cache the error to avoid
# repeated requests to the JWKS endpoint. The error may be temporary, so cache
# it for a short period of time.
_JWKS_ERROR_CACHE_TIMEOUT = timedelta(minutes=5).total_seconds()
# A sentinel value to indicate a cache miss.
_JWKS_DATA_MISSING = object()


logger = logging.getLogger(__name__)


def get_oidc_client_jwks(client, *, eager=False):
    """
    Retrieve the JWK data for an OIDC client by provider key.

    Arguments:
        client (OIDCClient):
            The provider key of the client to retrieve the JWK data for.
        eager (bool):
            Whether to bypass the cache and fetch the JWK data directly
            from the provider's JWKS endpoint.

            Use this to ensure that the keys are fresh and up-to-date.
            For example, on application startup or in a periodic task.

            Do not use this in the request/response cycle, it is a
            blocking operation that can significantly slow down the
            response time.

    Returns:
        jwcrypto.jwk.JWKSet | None:
            The JWK data for the OIDC client if available, or None if
            the data could not be retrieved.

    Raises:
        KeyError:
            If the client is not registered.
    """
    # A client must be registered to retrieve its JWK data.
    # There is no reason to fetch keys for an unregistered client.
    if client != oidc_clients.get_oidc_client(client.provider_key):
        # Only trust the given client if it's the exact same instance.
        raise KeyError(f"Client is not registered for {client.provider_key!r}.")

    cache_key = f"{_JWKS_CACHE_KEY_PREFIX}:{client.provider_key}"

    # Check the cache, unless explicitly requested to bypass it.
    if not eager:
        jwks_data = cache.get(cache_key, default=_JWKS_DATA_MISSING)

        if jwks_data and jwks_data is not _JWKS_DATA_MISSING:
            try:
                # Return immediately if the cached data is valid.
                return jwk.JWKSet.from_json(jwks_data)
            except jwk.InvalidJWKValue:
                # The cached data could not be decoded. Very unlikely.
                # Fall through to fetch the JWK data from the provider's JWKS endpoint.
                logger.exception(
                    "Failed to decode JWK data for %r from cache.",
                    client.provider_key,
                    extra={"jwks_data": jwks_data},
                )

        elif jwks_data is None:
            # The cache key is set to None, this indicates that a previous
            # attempt to fetch the JWK data failed. Return None to avoid
            # repeated requests to the JWKS endpoint.
            return None

        # The caller did not request eager fetching and the cache is empty.
        # Complain about the cache miss and reluctantly fetch the JWK data.
        # This is an unwanted situation and should be avoided.
        logger.warning(
            "JWK data for %r is not cached, reluctantly fetching from %r.",
            client.provider_key,
            client.jwks_uri,
        )

    # Fetch the JWK data from the provider's JWKS endpoint.
    try:
        response = requests.get(
            client.jwks_uri,
            headers={
                "Accept": "application/json",
            },
            # Timeout in seconds
            timeout=(
                5,  # Connect timeout
                30,  # Read timeout
            ),
        )
    except requests.RequestException:
        # The request failed.
        logger.exception(
            "Failed to fetch JWK data for %r from %r.",
            client.provider_key,
            client.jwks_uri,
        )
        cache.set(cache_key, None, timeout=_JWKS_ERROR_CACHE_TIMEOUT)
        return None

    # Check the response status code.
    try:
        response.raise_for_status()
    except requests.RequestException:
        # The server returned an error response.
        logger.exception(
            "Error after fetching JWK data for %r from %r: %s.",
            client.provider_key,
            client.jwks_uri,
            response.status_code,
            extra={
                "response_reason": response.reason,
                "response_text": response.text,
            },
        )
        cache.set(cache_key, None, timeout=_JWKS_ERROR_CACHE_TIMEOUT)
        return None

    # The server returned a successful response.
    try:
        jwks = jwk.JWKSet.from_json(response.text)
    except jwk.JWException:
        # The response could not be decoded.
        logger.exception(
            "Failed to decode JWK data for %r from %r.",
            client.provider_key,
            client.jwks_uri,
            extra={
                "response_text": response.text,
            },
        )
        cache.set(cache_key, None, timeout=_JWKS_ERROR_CACHE_TIMEOUT)
        return None

    # Success! Cache the JWK data for future use.
    cache.set(cache_key, response.text, timeout=_JWKS_DATA_CACHE_TIMEOUT)
    return jwks
