from .oauth2_provider import get_oauth2_provider_settings
from .oidc_clients import configure_oidc_clients

__all__ = [
    "configure_oidc_clients",
    "get_oauth2_provider_settings",
]
