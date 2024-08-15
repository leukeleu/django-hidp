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
        "link-account/",
        views.OIDCAccountLinkView.as_view(),
        name="link_account",
    ),
    path(
        "login/",
        views.OIDCLoginView.as_view(),
        name="login",
    ),
]
