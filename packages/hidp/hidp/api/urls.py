from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import (
    EmailChangeConfirmView,
    EmailChangeView,
    EmailVerificationResendView,
    EmailVerifiedView,
    LoginView,
    LogoutView,
    PasswordResetConfirmationView,
    PasswordResetRequestView,
    UserViewSet,
)

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("email-verified/", EmailVerifiedView.as_view(), name="email_verified"),
    path(
        "email-verified/resend/",
        EmailVerificationResendView.as_view(),
        name="email_verified_resend",
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
