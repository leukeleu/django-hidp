"""
Microsoft OpenID Connect provider.
"""

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


class MicrosoftOIDCClient(base.OIDCClient):
    provider_key = "microsoft"

    # Microsoft OpenID Connect endpoints
    # https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
    authorization_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"  # fmt: skip # noqa: E501
    token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"  # noqa: S105 (not a secret)
    userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo"
    jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
