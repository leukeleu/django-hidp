from django.apps import apps
from django.urls import path

from . import views

app_name = "hidp_api"

urlpatterns = [
    path("session/", views.SessionView.as_view(), name="session"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("signup/", views.SignupView.as_view(), name="signup"),
    path(
        "email-verification/resend/",
        views.EmailVerificationResendView.as_view(),
        name="email_verification_resend",
    ),
    path(
        "email-verification/verify/",
        views.EmailVerificationVerifyView.as_view(),
        name="email_verification_verify",
    ),
    path(
        "email-verification/confirm/",
        views.EmailVerificationConfirmView.as_view(),
        name="email_verification_confirm",
    ),
    path("users/me/", views.UserView.as_view(), name="user"),
    path(
        "password-reset/",
        views.PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),
    path(
        "password-reset/confirm/",
        views.PasswordResetConfirmationView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password/change/", views.PasswordChangeView.as_view(), name="password_change"
    ),
    path("password/set/", views.SetPasswordView.as_view(), name="set_password"),
    path("email-change/", views.EmailChangeView.as_view(), name="email_change"),
    path(
        "email-change/confirm/",
        views.EmailChangeConfirmView.as_view(),
        name="email_change_confirm",
    ),
]

if all(
    apps.is_installed(app)
    for app in (
        "hidp.otp",
        "django_otp.plugins.otp_totp",
        "django_otp.plugins.otp_static",
    )
):
    from . import otp_views

    urlpatterns += [
        path("otp/", otp_views.OTPStatusView.as_view(), name="otp"),
        path("otp/setup/", otp_views.OTPSetupView.as_view(), name="otp_setup"),
        path("otp/verify/", otp_views.OTPVerifyView.as_view(), name="otp_verify"),
        path(
            "otp/verify/recovery-code/",
            otp_views.OTPVerifyRecoveryCodeView.as_view(),
            name="otp_verify_recovery_code",
        ),
        path("otp/disable/", otp_views.OTPDisableView.as_view(), name="otp_disable"),
        path(
            "otp/disable/recovery-code/",
            otp_views.OTPDisableRecoveryCodeView.as_view(),
            name="otp_disable_recovery_code",
        ),
        path(
            "otp/recovery-codes/",
            otp_views.RecoveryCodesView.as_view(),
            name="otp_recovery_codes",
        ),
    ]
