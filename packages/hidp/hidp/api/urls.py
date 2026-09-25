from django.urls import path

from .views import (
    EmailChangeConfirmView,
    EmailChangeView,
    EmailVerificationConfirmView,
    EmailVerificationResendView,
    EmailVerificationVerifyView,
    LoginView,
    LogoutView,
    PasswordResetConfirmationView,
    PasswordResetRequestView,
    SessionView,
)

app_name = "hidp_api"

urlpatterns = [
    path("session/", SessionView.as_view(), name="session"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path(
        "email-verification/resend/",
        EmailVerificationResendView.as_view(),
        name="email_verification_resend",
    ),
    path(
        "email-verification/verify/",
        EmailVerificationVerifyView.as_view(),
        name="email_verification_verify",
    ),
    path(
        "email-verification/confirm/",
        EmailVerificationConfirmView.as_view(),
        name="email_verification_confirm",
    ),
    path(
        "password-reset/",
        PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "password-reset/confirm/",
        PasswordResetConfirmationView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "email-change/",
        EmailChangeView.as_view({"post": "create", "delete": "destroy"}),
        name="email_change",
    ),
    path(
        "email-change-confirm/",
        EmailChangeConfirmView.as_view(),
        name="email_change_confirm",
    ),
]
