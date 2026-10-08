"""Microsoft OpenID Connect provider."""

from . import base

# Follow the instructions from Microsoft on how to set up OpenID Connect on the
# Microsoft Identity Platform:
#
# https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
#
# Quick start:
#
# 1. Register a new application in the Entra portal:
#    https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade/quickStartType~/null/sourceType/Microsoft_AAD_IAM
#
#    - Set the application type to "Single Page Application".
#      This enables the Code Flow with PKCE, and avoids the need for a client secret.
#    - Pick the broadest account type possible (organization, personal, etc.)
#    - Set the redirect URI to: https://<domain>/login/oidc/callback/microsoft/
#      Private domains (e.g. *.local, *.test) are allowed.
#
# A single-tenant application cannot use the /common/ endpoints (AADSTS50194):
# pass its `tenant_id`.


class MicrosoftOIDCClient(base.OIDCClient):
    provider_key = "microsoft"

    # Microsoft OpenID Connect configuration:
    # https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
    issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
    authorization_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"  # fmt: skip # noqa: E501
    token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"  # noqa: S105 (not a secret)
    userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo"
    jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

    def __init__(
        self, *, client_id, client_secret=None, callback_base_url=None, tenant_id=None
    ):
        """
        Initialize the Microsoft OpenID Connect client.

        Arguments:
            client_id (``str``):
                The client ID provided by Microsoft.

            client_secret (``str``, `optional`):
                The client secret provided by Microsoft. Leave as None when using
                PKCE (recommended).

            callback_base_url (``str``, `optional`):
                Alternative base URL to use instead of the one of the request
                when constructing the callback URL.

            tenant_id (``str``, `optional`):
                The ID of the Entra tenant (a UUID or a verified domain name), for a
                single-tenant application. Its users are the only ones that can log
                in. Leave as None for the /common/ endpoints.
        """
        if tenant_id is not None:
            if not tenant_id or "/" in tenant_id:
                raise ValueError(
                    "Please provide a valid tenant ID (a UUID or verified domain"
                    " name, without slashes)."
                )
            base_url = f"https://login.microsoftonline.com/{tenant_id}"
            self.issuer = f"{base_url}/v2.0"
            self.authorization_endpoint = f"{base_url}/oauth2/v2.0/authorize"
            self.token_endpoint = f"{base_url}/oauth2/v2.0/token"
            self.jwks_uri = f"{base_url}/discovery/v2.0/keys"
        self.tenant_id = tenant_id
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            callback_base_url=callback_base_url,
        )

    def get_issuer(self, *, claims):
        if self.tenant_id is not None:
            # A single tenant has a single issuer.
            return self.issuer

        # Use the tenant ID from the claims to format the issuer URL.
        # The common issuer URL is used for all tenants, but the tenant ID
        # is required for the issuer URL to be valid.
        #
        # This is somewhat strange, but it's how Microsoft has set up
        # their OpenID Connect configuration.
        return (
            self.issuer.format(tenantid=tid)
            if (tid := claims.get("tid"))
            else self.issuer
        )
