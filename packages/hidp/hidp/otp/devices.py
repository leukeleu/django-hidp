from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.utils.translation import gettext_noop


def get_or_create_devices(user):
    """
    Get or create OTP devices for a user.

    This function is used to ensure that a user has a TOTP device and a backup static
    device. If the user already has these devices, they are returned. If not, they are
    created in unconfirmed state.
    """
    # Note we're using gettext_noop because we want to mark the strings for translation
    # here, but we don't want to translate them before saving them to the database.
    device, _created = TOTPDevice.objects.get_or_create(
        user=user,
        defaults={"name": gettext_noop("Authenticator app"), "confirmed": False},
    )
    backup_device, backup_device_created = StaticDevice.objects.get_or_create(
        user=user,
        defaults={"name": gettext_noop("Recovery codes"), "confirmed": False},
    )
    if backup_device_created or not backup_device.token_set.exists():
        for _ in range(10):
            backup_device.token_set.create(token=StaticToken.random_token())

    return device, backup_device
