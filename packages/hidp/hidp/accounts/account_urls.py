"""
Authentication URLs.

Provides the URL patterns for the base accounts features.

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

urlpatterns = register_urls + verifications_urls + auth_urls + recover_urls
