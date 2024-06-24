from django.urls import include, path

from hidp.config import urls as hidp_urls

urlpatterns = [
    path("", include(hidp_urls)),
]
