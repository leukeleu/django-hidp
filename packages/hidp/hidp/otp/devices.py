from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.utils.translation import trans_null

from hidp.otp.exceptions import MultipleOtpDevicesError, NoOtpDeviceError

# The translation happens in the template, allowing the device names below to be
# translated to the user's language when they are displayed, but also allowing
# user-defined 'legacy' device names to be displayed as-is.
TOTP_DEVICE_NAME = trans_null.pgettext("OTP device name", "Authenticator app")
STATIC_DEVICE_NAME = trans_null.pgettext("OTP device name", "Recovery codes")

# Warning: changing the names above will result in the old strings from the
# database not being translated. If you need to change the names, you should
# add the old names to the list below, wrapped in
# trans_null.pgettext("OTP device name", ...).
_LEGACY_DEVICE_NAMES = [
    # trans_null.pgettext("OTP device name", "Old name"),  # noqa: ERA001
]


def get_or_create_devices(user):
    """
    Get or create OTP devices for a user.

    This function is used to ensure that a user has a TOTP device and a backup static
    device. If the user already has these devices, they are returned. If not, they are
    created in unconfirmed state.
    """
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


def get_device_for_user(user, device_class):
    """
    Get the confirmed device of a specific class for a user.

    It is expected that there is exactly one confirmed device of the specified class
    for the user. If there are none or more than one, an exception is raised.
    """
    try:
        return device_class.objects.devices_for_user(user, confirmed=True).get()
    except device_class.DoesNotExist as exc:
        raise NoOtpDeviceError from exc
    except device_class.MultipleObjectsReturned as exc:
        raise MultipleOtpDevicesError from exc
