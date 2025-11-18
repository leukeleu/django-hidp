from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import (
    EmailChangeConfirmView,
    EmailChangeView,
    EmailVerificationResendView,
    EmailVerifiedView,
    LoginView,
    LogoutView,
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
