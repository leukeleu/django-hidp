"""
Authentication URLs

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

from django.urls import path

from . import views

app_name = "hidp_accounts"

register_urls = [
    path("signup/", views.RegistrationView.as_view(), name="register"),
]

auth_urls = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]

recover_urls = [
    path(
        "recover/",
        views.PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "recover/sent/",
        views.PasswordResetEmailSentView.as_view(),
        name="password_reset_email_sent",
    ),
    path(
        "recover/<uidb64>/<token>/",
        views.PasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "recover/complete/",
        views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]

urlpatterns = register_urls + auth_urls + recover_urls
