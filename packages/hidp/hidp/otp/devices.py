from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.utils.translation import trans_null

TOTP_DEVICE_NAME = trans_null.pgettext("OTP device name", "Authenticator app")
STATIC_DEVICE_NAME = trans_null.pgettext("OTP device name", "Recovery codes")


def get_or_create_devices(user):
    """
    Get or create OTP devices for a user.

    This function is used to ensure that a user has a TOTP device and a backup static
    device. If the user already has these devices, they are returned. If not, they are
    created in unconfirmed state.
    """
    # Note we're using gettext_noop because we want to mark the strings for translation
    # here, but we don't want to translate them before saving them to the database.
    totp_device, _created = TOTPDevice.objects.get_or_create(
        user=user,
        defaults={"name": TOTP_DEVICE_NAME, "confirmed": False},
    )
    static_device, backup_device_created = StaticDevice.objects.get_or_create(
        user=user,
        defaults={"name": STATIC_DEVICE_NAME, "confirmed": False},
    )
    if backup_device_created or not static_device.token_set.exists():
        reset_static_tokens(static_device)

    return totp_device, static_device


def reset_static_tokens(device, n=10):
    """
    Reset the static tokens for a device.

    This function deletes all existing static tokens for a device and creates 10 new
    ones. This amount should be sufficient for users to log in to disable MFA and
    during the time they have no access to their device but need to log in.
    """
    device.token_set.all().delete()
    for _ in range(n):
        device.token_set.create(token=StaticToken.random_token())
