from . import oauth_provider

__all__ = [
    "configure_django",
]


def configure_django(
    settings: dict,
    *,
    OIDC_RSA_PRIVATE_KEY: str,
):
    """
    Configure a Django project for the HiDP application.

    Arguments:
        settings: dict
            The globals() dictionary from the project's settings module.
            This dictionary will be modified in place.

        OIDC_RSA_PRIVATE_KEY: str
            The private RSA key used for OpenID Connect (OIDC) support.

            Generate a key using:

                openssl genrsa -out 'oidc.key' 4096

            The contents of the key file should be set as the OIDC_RSA_PRIVATE_KEY.


    Usage:
        Call this function directly in the settings module, after any necessary project
        specific settings have been configured. This will then (attempt to) configure
        apps, middleware, and other necessary settings.
    """
    oauth_provider.configure_django(settings, OIDC_RSA_PRIVATE_KEY=OIDC_RSA_PRIVATE_KEY)
