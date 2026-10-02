from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import UserViewSet

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
]
