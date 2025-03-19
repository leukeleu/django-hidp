from django.urls import path

from hidp.otp import views

app_name = "hidp_otp"

urlpatterns = [
    path("verify/", views.VerifyTOTPView.as_view(), name="verify"),
    path(
        "verify/recovery-code/",
        views.VerifyRecoveryCodeView.as_view(),
        name="verify-recovery-code",
    ),
]
