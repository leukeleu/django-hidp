"""Provide the basic interface, and some common functionality, for all providers."""

import urllib.parse


def _valid_provider_key(provider_key):
    """The provider key is valid when URL-encoding it does not change the value."""
    return urllib.parse.quote(provider_key) == provider_key


def _valid_callback_base_url(callback_base_url):
    """
    The callback base url is valid when the scheme is available and set to https,
    a netloc is present, the path is empty or points to the root, and all
    other parts are empty.
    """  # noqa: D205
    scheme, netloc, path, query, fragment = urllib.parse.urlsplit(callback_base_url)
    path = path.rstrip("/")  # Remove trailing slash so "/" becomes ""
    return scheme == "https" and netloc and not (path or query or fragment)


def _valid_endpoint(endpoint):
    """Communication with endpoints MUST utilize TLS."""
    # In order to prevent man-in-the-middle attacks, the authorization
    # server MUST require the use of TLS with [...] for any request sent
    # to the authorization and token endpoints.
    # https://datatracker.ietf.org/doc/html/rfc6749#section-10.9
    return endpoint.startswith("https://")


class OIDCClient:
    """
    Base class that needs to be overridden and configured according to the
    provider's specifications.

    Attributes:
        provider_key (``str``):
            Provider key, used to identify the provider in the application.

            This should be unique, descriptive, url-safe and, preferably, lowercase.

        name (``str``, `optional`):
            Provider name, used for display purposes. Will default to the capitalized
            provider key if not set.

        issuer (``str``):
            OpenID Connect issuer URL.

        authorization_endpoint (``str``):
            OpenID Connect authorization endpoint URL.

        token_endpoint (``str``):
            OpenID Connect token endpoint URL.

        userinfo_endpoint (``str``):
            OpenID Connect userinfo endpoint URL.

        jwks_uri (``str``):
            OpenID Connect JWKS URI.

        has_pkce_support (``boolean``):
            Whether the provider supports PKCE (Proof Key for Code Exchange).

            Note: Only set to True if the provider supports S256 as the code
            challenge method.

        client_id (``str``):
            Provider assigned client ID.

        client_secret (``str``, `optional`):
            Provider assigned client secret, if required for token exchange.

        callback_base_url (``str``, `optional`):
            Alternative base URL to use instead of the one of the request when
            constructing the callback URL.

    """  # noqa: D205

    provider_key = NotImplemented
    name = None

    # OpenID Connect configuration, can usually be extracted from the
    # provider's discovery document, commonly found at:
    # https://<provider>/.well-known/openid-configuration
    issuer = NotImplemented
    authorization_endpoint = NotImplemented
    token_endpoint = NotImplemented
    userinfo_endpoint = NotImplemented
    jwks_uri = NotImplemented

    # Note: Only set to True if the provider supports S256 as the code challenge method.
    has_pkce_support = True

    client_id = None
    client_secret = None
    callback_base_url = None

    def __init__(self, *, client_id, client_secret=None, callback_base_url=None):
        """
        Initialize the OpenID Connect client.

        Arguments:
            client_id (``str``):
                The client ID provided by the OpenID Connect provider.

            client_secret (``str``, `optional`):
                The client secret provided by the OpenID Connect provider.
                Leave as None if the provider does not require a client secret.

            callback_base_url (``str``, `optional`):
                Alternative base URL to use instead of the one of the request
                when constructing the callback URL.

                Some providers require the callback URL to be on a public domain,
                which may not be the case during development.
                Leave as None to use the request domain.

        """
        # Only allow instantiation if all required attributes are set.
        if any(
            value is NotImplemented
            for value in (
                self.provider_key,
                self.issuer,
                self.authorization_endpoint,
                self.token_endpoint,
                self.userinfo_endpoint,
                self.jwks_uri,
            )
        ):
            raise NotImplementedError(
                f"{self.__class__.__name__!r} misses (some of) the required attributes."
            )

        if not _valid_provider_key(self.provider_key):
            raise ValueError(
                f"'{self.__class__.__name__}.provider_key' is not URL-safe:"
                f" {self.provider_key!r}"
            )

        for endpoint in (
            self.authorization_endpoint,
            self.token_endpoint,
            self.userinfo_endpoint,
            self.jwks_uri,
        ):
            if not _valid_endpoint(endpoint):
                raise ValueError(
                    f"All endpoints must use TLS (https): {endpoint!r} does not."
                )

        if not self.has_pkce_support and client_secret is None:
            raise ValueError(
                f"Please provide a client secret."
                f" {self.__class__.__name__!r} declares it does not support PKCE,"
                " which means a client secret must be required for token exchange."
            )

        if callback_base_url is not None and not _valid_callback_base_url(
            callback_base_url
        ):
            raise ValueError(
                f"Invalid callback base url: {callback_base_url!r}."
                f" Should be in the form of 'https://<netloc>'"
                " (path, querystring and/or fragment are not allowed)."
            )

        # Validation passed, initialize the client.
        if self.name is None:
            self.name = self.provider_key.capitalize()

        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_base_url = callback_base_url

    def get_issuer(self, *, claims):
        """
        Return the expected value of the 'iss' claim in the ID token.

        Only override this method if absolutely necessary.

        Arguments:
            claims (``dict``):
                The claims from the ID token.

        Returns:
            ``str``:
                The expected issuer URL based on the claims.
        """
        # Some providers (like Microsoft) have a different issuer
        # for each tenant. This method allows to return the expected
        # issuer based on the claims.
        return self.issuer
