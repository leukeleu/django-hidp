from oauth2_provider import urls as oauth2_urls

from django.urls import include, path

urlpatterns = [path("", include(oauth2_urls))]
