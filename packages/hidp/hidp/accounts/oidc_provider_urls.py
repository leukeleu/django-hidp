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

from django_ratelimit.decorators import ratelimit
from oauth2_provider import views as oauth2_views

from django.urls import re_path

app_name = "oauth2_provider"

base_urlpatterns = [
    re_path(
        r"^authorize/$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                ratelimit(key="ip", method=ratelimit.ALL, rate="100/15m")(
                    oauth2_views.AuthorizationView.as_view()
                )
            )
        ),
        name="authorize",
    ),
    re_path(
        r"^token/$",
        ratelimit(key="ip", method="POST", rate="10/s")(
            ratelimit(key="ip", method="POST", rate="30/m")(
                ratelimit(key="ip", method="POST", rate="100/15m")(
                    oauth2_views.TokenView.as_view()
                )
            )
        ),
        name="token",
    ),
    re_path(
        r"^revoke_token/$",
        ratelimit(key="ip", method="POST", rate="10/s")(
            ratelimit(key="ip", method="POST", rate="30/m")(
                oauth2_views.RevokeTokenView.as_view()
            )
        ),
        name="revoke-token",
    ),
    re_path(
        r"^introspect/$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                oauth2_views.IntrospectTokenView.as_view()
            )
        ),
        name="introspect",
    ),
]

oidc_urlpatterns = [
    re_path(
        r"^\.well-known/openid-configuration/?$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                oauth2_views.ConnectDiscoveryInfoView.as_view()
            )
        ),
        name="oidc-connect-discovery-info",
    ),
    re_path(
        r"^\.well-known/jwks.json$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                oauth2_views.JwksInfoView.as_view()
            )
        ),
        name="jwks-info",
    ),
    re_path(
        r"^userinfo/$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                oauth2_views.UserInfoView.as_view()
            )
        ),
        name="user-info",
    ),
    re_path(
        r"^logout/$",
        ratelimit(key="ip", method=ratelimit.ALL, rate="10/s")(
            ratelimit(key="ip", method=ratelimit.ALL, rate="30/m")(
                oauth2_views.RPInitiatedLogoutView.as_view()
            )
        ),
        name="rp-initiated-logout",
    ),
]

urlpatterns = base_urlpatterns + oidc_urlpatterns
