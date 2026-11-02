"""OTP side effects shared by the HTML views and the API."""

import django_otp

from django.db import transaction


def confirm_setup(request, form):
    """Confirm the devices of a valid `OTPSetupForm` and verify the session."""
    form.save()
    django_otp.login(request, form.device)
    # The session is now fully authenticated, so it gets a new key.
    request.session.cycle_key()


def verify(request):
    """Verify the session with the device that validated the OTP form."""
    django_otp.login(request, request.user.otp_device)
    request.session.cycle_key()


@transaction.atomic
def disable(user):
    """Delete the confirmed OTP devices of `user`."""
    for device in django_otp.devices_for_user(user):
        device.delete()


def setup_requires_verification(user):
    """Whether `user` must verify with a confirmed device before setting up TOTP."""
    return django_otp.user_has_device(user) and not user.is_verified()
