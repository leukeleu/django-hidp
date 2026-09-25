"""OTP side effects shared by the HTML views and the API."""

import django_otp

from django.db import transaction

from .devices import reset_static_tokens


def confirm_setup(request, form):
    """Confirm the devices of a valid `OTPSetupForm` and verify the session."""
    form.save()
    django_otp.login(request, form.device)


def verify(request):
    """Verify the session with the device that validated the OTP form."""
    django_otp.login(request, request.user.otp_device)


@transaction.atomic
def disable(user):
    """Delete the confirmed OTP devices of `user`."""
    for device in django_otp.devices_for_user(user):
        device.delete()


def regenerate_recovery_codes(device):
    """Replace the recovery codes of the static `device`."""
    reset_static_tokens(device)


def setup_requires_verification(user):
    """Whether `user` must verify with a confirmed device before setting up TOTP."""
    is_verified = getattr(user, "is_verified", None)
    return django_otp.user_has_device(user) and not (is_verified and is_verified())
