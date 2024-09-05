"""Google OpenID Connect provider."""

from . import base

# Follow the instructions from Google on how to set up
# OpenID Connect on the Google Identity Platform:
# https://developers.google.com/identity/openid-connect/openid-connect
#
# Quick start:
#
# 1. Create a new project in the Google Cloud Console, and make sure to select it
#    as the active project. Skip this step if you already have a project.
#    https://console.cloud.google.com/projectcreate
#
# 2. Configure the OAuth consent screen. This is required for the OAuth 2.0 flow,
#    it is not possible to obtain OAuth 2.0 credentials without configuring it.
#    https://console.cloud.google.com/apis/credentials/consent
#
#    Note:
#    - Uploading a logo will require verification of the application.
#      Avoid uploading a logo if you are creating a test application.
#    - App domains and authorized domains are not required for testing.
#      They can be left empty.
#
# 3. Obtain OAuth 2.0 credentials:
#    https://console.cloud.google.com/apis/credentials/oauthclient
#
#    - Select "Web application" as the application type.
#    - Configure the authorized redirect URI:
#
#      https://<domain>/login/oidc/callback/google/
#
#      Note: The redirect URI must be a valid *public* URL or localhost.
#      For development use either localhost or a hosts file entry to
#      map a public domain to a local development server.
#
#      Tip: Use local.<production-domain> to avoid squatting on a real domain.
#   - Save the client ID and client secret, they will be required for the
#     OpenID Connect client configuration. Make sure to treat the client secret
#     as a secret, do not expose it in the source code or client-side code.


class GoogleOIDCClient(base.OIDCClient):
    provider_key = "google"

    # Google OpenID Connect configuration:
    # https://accounts.google.com/.well-known/openid-configuration
    issuer = "https://accounts.google.com"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"  # noqa: S105 (not a secret)
    userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"

    def __init__(self, *, client_id, client_secret, **kwargs):
        # Google requires both client_id and client_secret to be provided.
        super().__init__(client_id=client_id, client_secret=client_secret, **kwargs)
