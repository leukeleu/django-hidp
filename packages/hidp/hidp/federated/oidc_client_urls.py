"""
OIDC client URLs.

Provides the URL patterns for OIDC client authentication and registration.

Include this module in the root URL configuration:

    from hidp.federated import oidc_client_urls

    urlpatterns = [
        path("login/oidc/", include(oidc_client_urls)),
    ]

This module also defines the namespace `hidp_oidc_client` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("hidp_oidc_client:authenticate", kwargs={"provider_key": "example"})
"""

from django.urls import path

from . import views

app_name = "hidp_oidc_client"

urlpatterns = [
    path(
        "authenticate/<slug:provider_key>/",
        views.OIDCAuthenticationRequestView.as_view(),
        name="authenticate",
    ),
    path(
        "reauthenticate/<slug:provider_key>/",
        views.OIDCAuthenticationRequestView.as_view(
            extra_authentication_request_params={
                "prompt": "login",
                "max_age": 0,
            }
        ),
        name="reauthenticate",
    ),
    path(
        "callback/<slug:provider_key>/",
        views.OIDCAuthenticationCallbackView.as_view(),
        name="callback",
    ),
    path(
        "register/",
        views.OIDCRegistrationView.as_view(),
        name="register",
    ),
    path(
        "login/",
        views.OIDCLoginView.as_view(),
        name="login",
    ),
]
