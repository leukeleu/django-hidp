from django.urls import path

from . import views

urlpatterns = [
    path("rate_limited_view/", views.rate_limited_view, name="rate_limited_view"),
]
