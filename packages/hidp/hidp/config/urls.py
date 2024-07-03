from django.urls import include, path

from ..accounts import auth_urls, oidc_provider_urls

urlpatterns = [
    path("", include(auth_urls)),
    path("o/", include(oidc_provider_urls)),
]
