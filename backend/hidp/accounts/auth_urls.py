"""
Authentication URLs

Provides the URL patterns for the authentication views (login, logout).

Include this module in the root URL configuration:

    from hidp.accounts import auth_urls

    urlpatterns = [
        path("", include(auth_urls)),
    ]

This module also defines the namespace `auth` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("auth:login")
"""

from django.urls import path

from . import views

app_name = "auth"

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
]
