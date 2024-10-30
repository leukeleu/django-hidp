"""
OIDC Management URLs.

Provides the URL patterns for managing OIDC linked services.

Include this module in the root URL configuration:

    from hidp.federated import oidc_management_urls

    urlpatterns = [
        path("manage/oidc/", include(oidc_management_urls)),
    ]

This module also defines the namespace `hidp_oidc_management` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("hidp_oidc_management:linked_services")
"""

from django.urls import path

from . import views

app_name = "hidp_oidc_management"

urlpatterns = [
    path(
        "",
        views.OIDCLinkedServicesView.as_view(),
        name="linked_services",
    ),
    path(
        "link-account/",
        views.OIDCAccountLinkView.as_view(),
        name="link_account",
    ),
    path(
        "link-account/<str:provider_key>/done/",
        views.OIDCAccountLinkDoneView.as_view(),
        name="link_account_done",
    ),
    path(
        "unlink-account/<str:provider_key>/",
        views.OIDCAccountUnlinkView.as_view(),
        name="unlink_account",
    ),
    path(
        "unlink-account/<str:provider_key>/done/",
        views.OIDCAccountUnlinkDoneView.as_view(),
        name="unlink_account_done",
    ),
]
