from django.contrib import admin
from django.views.generic.base import RedirectView
from django.urls import include, path

from hidp.config import urls as hidp_urls

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="auth:login"), name="root"),
    path("", include(hidp_urls)),
]
