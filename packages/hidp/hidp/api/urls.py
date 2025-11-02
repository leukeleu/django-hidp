from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import SessionViewSet, UserViewSet

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")
router.register("sessions", SessionViewSet, basename="session")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
]
