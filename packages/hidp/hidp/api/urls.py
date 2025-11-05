from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import (
    PasswordResetConfirmationView,
    PasswordResetRequestView,
    UserViewSet,
)

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
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
]
