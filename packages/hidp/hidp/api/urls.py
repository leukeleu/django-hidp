from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import (
    EmailVerificationResendView,
    EmailVerifiedView,
    LoginView,
    UserViewSet,
)

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
    path("login/", LoginView.as_view(), name="login"),
    path("email-verified/", EmailVerifiedView.as_view(), name="email_verified"),
    path(
        "email-verified/resend/",
        EmailVerificationResendView.as_view(),
        name="email_verified_resend",
    ),
]
