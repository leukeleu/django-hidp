from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("users/me/", views.UserView.as_view(), name="user"),
]
