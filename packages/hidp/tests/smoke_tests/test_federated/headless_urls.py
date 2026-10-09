from django.urls import include, path

urlpatterns = [
    path("", include("hidp.config.headless_urls")),
    path("api/auth/", include("hidp.api.urls")),
]
