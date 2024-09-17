from django.urls import include, path
from django.views.generic.base import RedirectView

from hidp.config import urls as hidp_urls

from .router import router

urlpatterns = [
    # Project
    path(
        "",
        RedirectView.as_view(pattern_name="hidp_accounts:manage_account"),
        name="root",
    ),
    path("", include(hidp_urls)),
    *router.urls,
]
