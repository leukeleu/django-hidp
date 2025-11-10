from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import LoginView, LogoutView, UserViewSet

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
