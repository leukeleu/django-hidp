from django.urls import path

from hidp.otp import views

app_name = "hidp_otp"

urlpatterns = [
    path("verify/", views.VerifyOTPView.as_view(), name="verify"),
]
