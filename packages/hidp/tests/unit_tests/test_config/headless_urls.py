from django.urls import include, path

urlpatterns = [
    path("api/", include("hidp.api.urls")),
]
