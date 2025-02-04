from django.apps import apps
from django.urls import include, path

from ..accounts import account_management_urls, account_urls
from ..federated import oidc_client_urls, oidc_management_urls

urlpatterns = [
    path("", include(account_urls)),
    path("login/oidc/", include(oidc_client_urls)),
    path("manage/", include(account_management_urls)),
    path("manage/oidc/", include(oidc_management_urls)),
]

if all(
    apps.is_installed(app)
    for app in (
        "hidp.otp",
        "django_otp.plugins.otp_totp",
        "django_otp.plugins.otp_static",
    )
):
    from ..otp import otp_management_urls

    urlpatterns += [
        path("manage/otp/", include(otp_management_urls)),
        path("otp/", include("hidp.otp.otp_urls")),
    ]

if apps.is_installed("hidp.oidc_provider"):
    urlpatterns += [
        path("o/", include("hidp.oidc_provider.urls")),
        path("api/", include("hidp.api.urls")),
    ]
