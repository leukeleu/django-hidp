from django.conf import settings
from django.urls import include, path

from ..accounts import account_management_urls, account_urls
from ..federated import oidc_client_urls, oidc_management_urls
from ..otp import otp_management_urls

urlpatterns = [
    path("", include(account_urls)),
    path("login/oidc/", include(oidc_client_urls)),
    path("manage/", include(account_management_urls)),
    path("manage/oidc/", include(oidc_management_urls)),
]

if "hidp.otp" in settings.INSTALLED_APPS:
    urlpatterns += [
        path("manage/otp/", include(otp_management_urls)),
    ]

if "hidp.oidc_provider" in settings.INSTALLED_APPS:
    urlpatterns += [
        path("o/", include("hidp.oidc_provider.urls")),
        path("api/", include("hidp.api.urls")),
    ]
