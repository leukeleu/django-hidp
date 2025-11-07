from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import EmailChangeConfirmView, EmailChangeView, UserViewSet

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
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
