"""
Authentication URLs

Provides the URL patterns for the authentication views (login, logout).

Include this module in the root URL configuration:

    from hidp.accounts import auth_urls

    urlpatterns = [
        path("", include(auth_urls)),
    ]

This module also defines the namespace `hidp_accounts` for these URLs.

Include this namespace when reversing URLs, for example:

    reverse("hidp_accounts:login")
"""

from django.urls import path

from . import views

app_name = "hidp_accounts"

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]
