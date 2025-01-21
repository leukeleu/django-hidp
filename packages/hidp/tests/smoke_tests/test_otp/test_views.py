from django.test import TestCase
from django.urls import reverse

from hidp.test.factories import user_factories
from hidp.test.factories.otp_factories import StaticDeviceFactory, TOTPDeviceFactory


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
