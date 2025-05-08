from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

from hidp.config import urls as hidp_urls

urlpatterns = [
    # Project
    path(
        "",
        RedirectView.as_view(pattern_name="hidp_account_management:manage_account"),
        name="root",
    ),
    # Hello, ID Please
    path(
        "django-admin/login/",
        RedirectView.as_view(pattern_name="hidp_accounts:login"),
    ),
    path("django-admin/", admin.site.urls),
    path("", include(hidp_urls)),
]
