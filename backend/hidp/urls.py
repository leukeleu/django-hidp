from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

from hidp.config import urls as hidp_urls

from .router import router

urlpatterns = [
    # Project
    path("", RedirectView.as_view(pattern_name="auth:login"), name="root"),
    path("", include(hidp_urls)),
    *router.urls,
    # Django Admin
    path("django-admin/", admin.site.urls),
]
