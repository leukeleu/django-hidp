"""
Authentication URLs.

Provides the URL patterns for the accounts views (register, login, logout).

Include this module in the root URL configuration:

    from hidp.accounts import account_urls

    urlpatterns = [
        path("", include(account_urls)),
    ]

This module also defines the namespace `hidp_accounts` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("hidp_accounts:login")
"""

from django.urls import include, path

from . import views

app_name = "hidp_accounts"

register_urls = [
    path("signup/", views.RegistrationView.as_view(), name="register"),
    path("terms-of-service/", views.TermsOfServiceView.as_view(), name="tos"),
]

verifications_urls = [
    path(
        "verify/<token>/sent/",
        views.EmailVerificationRequiredView.as_view(),
        name="email_verification_required",
    ),
    path(
        "verify/<token>/verify/",
        views.EmailVerificationView.as_view(),
        name="verify_email",
    ),
    path(
        "verify/complete/",
        views.EmailVerificationCompleteView.as_view(),
        name="email_verification_complete",
    ),
]

auth_urls = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]

recover_password_urls = [
    path(
        "",
        views.PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "sent/",
        views.PasswordResetEmailSentView.as_view(),
        name="password_reset_email_sent",
    ),
    path(
        "<uidb64>/<token>/",
        views.PasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "complete/",
        views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]

recover_urls = [
    path(
        "recover/password/",
        include(recover_password_urls),
    )
]

account_urls = [
    path("", views.ManageAccountView.as_view(), name="manage_account"),
    path("edit-account/", views.EditAccountView.as_view(), name="edit_account"),
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
        "manage/set-password/",
        views.SetPasswordView.as_view(),
        name="set_password",
    ),
    path(
        "manage/set-password/done/",
        views.SetPasswordDoneView.as_view(),
        name="set_password_done",
    ),
]

linked_services_urls = [
    path(
        "linked-services/",
        views.OIDCLinkedServicesView.as_view(),
        name="oidc_linked_services",
    ),
]

management_urls = [
    path(
        "manage/",
        include(
            account_urls
            + change_password_urls
            + set_password_urls
            + linked_services_urls
        ),
    ),
]

urlpatterns = (
    register_urls + verifications_urls + auth_urls + recover_urls + management_urls
)
