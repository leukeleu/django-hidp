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
        "disable/recovery-code/",
        views.OTPDisableViewRecoveryCode.as_view(),
        name="disable-recovery-code",
    ),
    path(
        "recovery-codes/",
        views.OTPRecoveryCodes.as_view(),
        name="recovery-codes",
    ),
    path(
        "setup/done/",
        views.OTPSetupDeviceDoneView.as_view(),
        name="setup-device-done",
    ),
    path(
        "setup/",
        views.OTPSetupDeviceView.as_view(),
        name="setup",
    ),
]
