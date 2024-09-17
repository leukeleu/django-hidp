from rest_framework.routers import DefaultRouter

from django.urls import include, path

router = DefaultRouter()

app_name = "api"

urlpatterns = [
    path("", include(router.urls)),
]
