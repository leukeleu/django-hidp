from django.urls import include, path
from django.views.generic.base import RedirectView

from hidp.accounts import account_registration_urls
from hidp.config import urls as hidp_urls

urlpatterns = [
    # Project
    path(
        "",
        RedirectView.as_view(pattern_name="hidp_account_management:manage_account"),
        name="root",
    ),
    path("", include(hidp_urls)),
    path("", include(account_registration_urls)),
]
