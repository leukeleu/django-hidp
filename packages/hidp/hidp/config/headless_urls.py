"""
The views of HIdP that a headless project mounts next to `hidp.api.urls`.

Logging in with an OIDC provider redirects through these views, and they serve
HIdP's OIDC provider when it is installed. Every page is the frontend's, through
`HIDP_FRONTEND_URLS`.

Include this module in the root URL configuration:

    from django.urls import include, path

    urlpatterns = [
        path("", include("hidp.config.headless_urls")),
        path("api/auth/", include("hidp.api.urls")),
    ]
"""

from django.apps import apps
from django.urls import include, path

from ..federated import oidc_client_urls

urlpatterns = [
    path("login/oidc/", include(oidc_client_urls)),
    # The user endpoint for OAuth2 access tokens.
    path("api/", include("hidp.api.user_urls")),
]

if apps.is_installed("hidp.oidc_provider"):
    urlpatterns += [
        path("o/", include("hidp.oidc_provider.urls")),
    ]
