from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

from .accounts import urls as account_urls
from .router import router

urlpatterns = [
    # Project
    path("", RedirectView.as_view(pattern_name="accounts:login"), name="root"),
    path("", include(account_urls)),
    *router.urls,
    # Django Admin
    path("django-admin/", admin.site.urls),
]
