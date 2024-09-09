from django.conf import settings
from django.urls import include, path

from ..accounts import account_urls
from ..federated import oidc_client_urls

urlpatterns = [
    path("", include(account_urls)),
    path("login/oidc/", include(oidc_client_urls)),
]

if "hidp.oidc_provider" in settings.INSTALLED_APPS:
    urlpatterns += [
        path("o/", include("hidp.oidc_provider.urls")),
    ]
