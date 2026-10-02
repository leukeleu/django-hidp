from django.urls import path

from . import views

urlpatterns = [
    path("rate_limited_view/", views.rate_limited_view, name="rate_limited_view"),
    path("rate_limited_api_view/", views.RateLimitedAPIView.as_view()),
]
