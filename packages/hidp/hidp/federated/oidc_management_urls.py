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
        "unlink-account/<str:provider_key>/",
        views.OIDCAccountUnlinkView.as_view(),
        name="unlink_account",
    ),
]
