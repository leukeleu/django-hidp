"""
Account management URLs.

Provides the URL patterns for the account management features.

Include this module in the root URL configuration:

    from hidp.accounts import account_management_urls

    urlpatterns = [
        path("manage/", include(account_management_urls)),
    ]

This module also defines the namespace `hidp_account_management` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("hidp_account_management:manage_account")
"""

from django.urls import path

from . import views

app_name = "hidp_account_management"

account_urls = [
    path("", views.ManageAccountView.as_view(), name="manage_account"),
    path("edit-account/", views.EditAccountView.as_view(), name="edit_account"),
    path(
        "edit-account/done/",
        views.EditAccountDoneView.as_view(),
        name="edit_account_done",
    ),
]

change_password_urls = [
    path(
        "change-password/",
        views.PasswordChangeView.as_view(),
        name="change_password",
    ),
    path(
        "change-password/done/",
        views.PasswordChangeDoneView.as_view(),
        name="change_password_done",
    ),
]

set_password_urls = [
    path(
        "set-password/",
        views.SetPasswordView.as_view(),
        name="set_password",
    ),
    path(
        "set-password/done/",
        views.SetPasswordDoneView.as_view(),
        name="set_password_done",
    ),
]

change_email_urls = [
    path(
        "change-email/",
        views.EmailChangeRequestView.as_view(),
        name="email_change_request",
    ),
    path(
        "change-email/sent/",
        views.EmailChangeRequestSentView.as_view(),
        name="email_change_request_sent",
    ),
    path(
        "change-email-confirm/<token>/",
        views.EmailChangeConfirmView.as_view(),
        name="email_change_confirm",
    ),
    path(
        "change-email-complete/",
        views.EmailChangeCompleteView.as_view(),
        name="email_change_complete",
    ),
    path(
        "change-email-cancel/",
        views.EmailChangeCancelView.as_view(),
        name="email_change_cancel",
    ),
    path(
        "change-email-cancel-done/",
        views.EmailChangeCancelDoneView.as_view(),
        name="email_change_cancel_done",
    ),
]

urlpatterns = (
    account_urls + change_password_urls + set_password_urls + change_email_urls
)
