"""
OAuth2 Provider URLs

Provides the URL patterns for OAuth2 and OpenID Connect (OIDC) endpoints.

Include this module in the root URL configuration:

    from hidp.accounts import oidc_provider_urls

    urlpatterns = [
        path("o/", include(oidc_provider_urls)),
    ]

This module uses the `oauth2_provider` namespace for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("oauth2_provider:authorize")

Does **not** include application management views. Applications can be managed
using the Django Admin interface.
"""

from oauth2_provider import urls as oauth2_urls

from django.urls import include, path

urlpatterns = [
    path(
        "",
        include(
            (
                oauth2_urls.base_urlpatterns + oauth2_urls.oidc_urlpatterns,
                oauth2_urls.app_name,
            ),
        ),
    )
]
