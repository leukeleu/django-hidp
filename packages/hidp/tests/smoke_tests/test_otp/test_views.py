from django.test import TestCase
from django.urls import reverse

from hidp.test.factories import user_factories
from hidp.test.factories.otp_factories import (
    StaticDeviceFactory,
    StaticTokenFactory,
    TOTPDeviceFactory,
)


class TestOTPOverview(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp_management:manage"))
        self.assertRedirects(
            response, f"/login/?next={reverse('hidp_otp_management:manage')}"
        )

    def test_get_otp_overview_without_devices(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:manage"))
        self.assertContains(response, "Authenticator app: not configured")
        self.assertContains(response, "Recovery codes: not configured")

    def test_get_otp_overview_with_devices(self):
        TOTPDeviceFactory(user=self.user, confirmed=True)
        StaticDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:manage"))
        self.assertContains(response, "Authenticator app: configured")
        self.assertContains(response, "Recovery codes: configured")

    def test_get_otp_overview_with_unconfirmed_devices(self):
        TOTPDeviceFactory(user=self.user, confirmed=False)
        StaticDeviceFactory(user=self.user, confirmed=False)
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:manage"))
        self.assertContains(response, "Authenticator app: not configured")
        self.assertContains(response, "Recovery codes: not configured")


class TestOTPDisable(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp_management:disable"))
        self.assertRedirects(
            response, f"/login/?next={reverse('hidp_otp_management:disable')}"
        )

    def test_get_otp_disable(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:disable"))
        self.assertTemplateUsed(response, "hidp/otp/disable.html")

    def test_post_otp_disable(self):
        TOTPDeviceFactory(user=self.user, confirmed=True)
        static_device = StaticDeviceFactory(user=self.user, confirmed=True)
        StaticTokenFactory.create_batch(9, device=static_device)
        StaticTokenFactory(device=static_device, token="static-token")
        self.client.force_login(self.user)

        form_data = {
            "otp_device": static_device.persistent_id,
            "otp_token": "static-token",
        }
        response = self.client.post(reverse("hidp_otp_management:disable"), form_data)
        self.assertRedirects(response, reverse("hidp_otp_management:manage"))
        self.assertFalse(self.user.totpdevice_set.exists())
        self.assertFalse(self.user.staticdevice_set.exists())
