from django.urls import path

from . import views

app_name = "hidp_otp_management"

urlpatterns = [
    path(
        "",
        views.OTPOverviewView.as_view(),
        name="manage",
    ),
    path(
        "disable/",
        views.OTPDisableView.as_view(),
        name="disable",
    ),
    path(
        "recovery-codes/",
        views.OTPRecoveryCodes.as_view(),
        name="recovery-codes",
    ),
]
