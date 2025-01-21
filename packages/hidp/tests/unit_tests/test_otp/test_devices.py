from django.test import TestCase

from hidp.otp.devices import get_or_create_devices
from hidp.test.factories import otp_factories, user_factories


class TestGetOrCreateDevices(TestCase):
    def test_get_or_create_devices(self):
        user = user_factories.UserFactory()
        totp_device, static_device = get_or_create_devices(user)
        self.assertEqual(totp_device.name, "Authenticator app")
        self.assertFalse(
            totp_device.confirmed, "Expected TOTP device to be unconfirmed"
        )
        self.assertEqual(static_device.name, "Recovery codes")
        self.assertFalse(
            static_device.confirmed, "Expected static device to be unconfirmed"
        )
        self.assertEqual(static_device.token_set.count(), 10)

    def test_get_or_create_devices_existing(self):
        user = user_factories.UserFactory()
        existing_totp_device = otp_factories.TOTPDeviceFactory(
            user=user, name="My existing authenticator app", confirmed=True
        )
        existing_static_device = otp_factories.StaticDeviceFactory(
            user=user, name="My existing backup tokens", confirmed=True
        )
        totp_device, static_device = get_or_create_devices(user)

        self.assertEqual(existing_totp_device, totp_device)
        self.assertEqual(existing_static_device, static_device)

        self.assertEqual(totp_device.name, "My existing authenticator app")
        self.assertTrue(totp_device.confirmed, "Expected TOTP device to be confirmed")
        self.assertEqual(static_device.name, "My existing backup tokens")
        self.assertTrue(
            static_device.confirmed, "Expected static device to be confirmed"
        )
        self.assertEqual(static_device.token_set.count(), 10)

    def test_static_tokens_are_not_replenished(self):
        user = user_factories.UserFactory()
        existing_static_device = otp_factories.StaticDeviceFactory(
            user=user, name="My existing backup tokens", confirmed=True
        )
        existing_static_device.token_set.create(token="old token")

        _totp_device, static_device = get_or_create_devices(user)
        self.assertEqual(static_device.token_set.count(), 1)
        self.assertEqual(static_device.token_set.first().token, "old token")
