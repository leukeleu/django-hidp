from django.urls import include, path

urlpatterns = [
    path("", include("hidp.config.urls")),
    path("api/", include("hidp.api.urls")),
]
