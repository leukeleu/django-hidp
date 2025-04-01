from django.urls import path

from . import views

app_name = "hidp_accounts_registration"

register_urls = [
    path("signup/", views.RegistrationView.as_view(), name="register"),
    path("terms-of-service/", views.TermsOfServiceView.as_view(), name="tos"),
]

urlpatterns = register_urls
