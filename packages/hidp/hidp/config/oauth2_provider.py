"""Configuration for Django OAuth Toolkit (DOT) in the HIdP application."""

from datetime import timedelta

OAUTH2_PROVIDER = {
    # The number of seconds an access token remains valid.
    # Requesting a protected resource after this duration will fail.
    # Keep this value high enough so clients can cache the token for
    # a reasonable amount of time.
    #
    # Default in DOT is 1 hour (3600 seconds).
    "ACCESS_TOKEN_EXPIRE_SECONDS": timedelta(hours=12).total_seconds(),
    # The number of seconds an authorization code remains valid.
    # Requesting an access token after this duration will fail.
    # RFC6749 Section 4.1.2 recommends a 10 minute (600 seconds) duration.
    #
    # Default in DOT is 1 minute (60 seconds).
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": timedelta(minutes=10).total_seconds(),
    # The number of seconds before a refresh token gets removed from the database
    # by the cleartokens management command.
    #
    # NOTE: This value is completely ignored when validating refresh tokens.
    #
    # If cleartokens runs daily the maximum delay before a refresh token
    # is removed is REFRESH_TOKEN_EXPIRE_SECONDS + 1 day.
    #
    # Default in DOT is None (never remove refresh tokens).
    "REFRESH_TOKEN_EXPIRE_SECONDS": timedelta(days=90).total_seconds(),
    # The number of seconds between when a refresh token is first used
    # and when it is expired.
    # The most common case for this are native mobile applications
    # that run into issues of network connectivity during the refresh cycle
    # and are unable to complete the full request/response life cycle.
    # Without a grace period the application only has a consumed
    # refresh token and the only recourse is to have the user re-authenticate.
    #
    # Default in DOT is 0 (no grace period).
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": timedelta(minutes=10).total_seconds(),
    # Enable OpenID Connect support.
    # Default in DOT is False.
    "OIDC_ENABLED": True,
    # Enable and configure RP-Initiated Logout
    # Default in DOT is False
    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": None,
    # A list of scopes that can be requested by clients, with descriptions.
    "SCOPES": {
        # Default OpenID Connect scope
        # https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
        "openid": "OpenID Connect",
        # OpenID Connect profile scope
        "profile": "View basic profile information",
        # OpenID Connect email scope
        "email": "View email address",
    },
    "DEFAULT_SCOPES": ["openid"],
    # Custom OAuth2Validator that maps OIDC scopes to the correct user attributes
    "OAUTH2_VALIDATOR_CLASS": "hidp.oidc_provider.oauth_validators.OAuth2Validator",
    # RFC 9700 / OAuth 2.1 posture. HIdP supports the Authorization Code
    # flow with PKCE only; these gates make the server reject everything
    # else and keep the discovery documents consistent with that.
    "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
    "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT": True,
    "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,
    "REFRESH_TOKEN_REUSE_PROTECTION": True,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["https"],
    # Opt-in: requires REFRESH_TOKEN_GRACE_PERIOD_SECONDS == 0
    # "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE": True,
}

# XXX: Everything above this line is included verbatim in the documentation!
#      If this line number changes, update `literalinclude` in the
#      "Adding/overriding Django OAuth Toolkit settings" section of
#      `docs/configure-as-oidc-provider.md` to end at the correct line number.


def get_oauth2_provider_settings(
    *,
    OIDC_RSA_PRIVATE_KEY: str,
):
    """
    Configure Django OAuth Toolkit for the HIdP application.

    Arguments:
        OIDC_RSA_PRIVATE_KEY: str
            The private RSA key used for OpenID Connect (OIDC) support.

            Generate a key using:

                openssl genrsa -out 'oidc.key' 4096

            The contents of the key file should be set as the OIDC_RSA_PRIVATE_KEY.

    Usage:

        In the Django settings module, call this function with the necessary
        configuration values and assign the result to the OAUTH2_PROVIDER setting:

            OAUTH2_PROVIDER = configure(OIDC_RSA_PRIVATE_KEY=...)
    """
    return OAUTH2_PROVIDER | {
        "OIDC_RSA_PRIVATE_KEY": OIDC_RSA_PRIVATE_KEY,
    }
