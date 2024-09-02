"""
OAuth2 Provider URLs.

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

from oauth2_provider import views as oauth2_views

from django.urls import path

from ..rate_limit.decorators import rate_limit_default, rate_limit_strict
from . import views

app_name = "oauth2_provider"

base_urlpatterns = [
    path(
        "authorize/",
        rate_limit_strict(views.AuthorizationView.as_view()),
        name="authorize",
    ),
    path(
        "token/",
        rate_limit_strict(oauth2_views.TokenView.as_view()),
        name="token",
    ),
    path(
        "revoke_token/",
        rate_limit_default(oauth2_views.RevokeTokenView.as_view()),
        name="revoke-token",
    ),
    path(
        "introspect/",
        rate_limit_default(oauth2_views.IntrospectTokenView.as_view()),
        name="introspect",
    ),
]

oidc_urlpatterns = [
    path(
        ".well-known/openid-configuration",
        rate_limit_default(oauth2_views.ConnectDiscoveryInfoView.as_view()),
        name="oidc-connect-discovery-info",
    ),
    path(
        ".well-known/jwks.json",
        rate_limit_default(oauth2_views.JwksInfoView.as_view()),
        name="jwks-info",
    ),
    path(
        "userinfo/",
        rate_limit_default(oauth2_views.UserInfoView.as_view()),
        name="user-info",
    ),
    path(
        "logout/",
        rate_limit_default(views.RPInitiatedLogoutView.as_view()),
        name="rp-initiated-logout",
    ),
]

urlpatterns = base_urlpatterns + oidc_urlpatterns
