from http import HTTPStatus

from django.test import TestCase
from django.urls import reverse

from hidp.otp.devices import reset_static_tokens
from hidp.test.factories import otp_factories, user_factories


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
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:manage"))
        self.assertContains(response, "Authenticator app: configured")
        self.assertContains(response, "Recovery codes: configured")

    def test_get_otp_overview_with_unconfirmed_devices(self):
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=False)
        otp_factories.StaticDeviceFactory(user=self.user, confirmed=False)
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
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        static_device = otp_factories.StaticDeviceFactory(
            user=self.user, confirmed=True
        )
        otp_factories.StaticTokenFactory.create_batch(9, device=static_device)
        otp_factories.StaticTokenFactory(device=static_device, token="static-token")
        self.client.force_login(self.user)

        form_data = {
            "otp_device": static_device.persistent_id,
            "otp_token": "static-token",
        }
        response = self.client.post(reverse("hidp_otp_management:disable"), form_data)
        self.assertRedirects(response, reverse("hidp_otp_management:manage"))
        self.assertFalse(self.user.totpdevice_set.exists())
        self.assertFalse(self.user.staticdevice_set.exists())


class TestOTPRecoveryCodesView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp_management:recovery-codes"))
        self.assertRedirects(
            response,
            f"/login/?next={reverse('hidp_otp_management:recovery-codes')}",
        )

    def test_no_static_device(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:recovery-codes"))
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_get_recovery_codes(self):
        device = otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        reset_static_tokens(device)
        current_tokens = list(device.token_set.values_list("token", flat=True))
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:recovery-codes"))
        self.assertContains(response, "Recovery codes")
        self.assertContains(response, "Generate new codes")
        for token in current_tokens:
            self.assertContains(response, token)

    def test_post_reset_recovery_codes(self):
        device = otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        reset_static_tokens(device)
        current_tokens = set(device.token_set.values_list("token", flat=True))
        self.client.force_login(self.user)
        response = self.client.post(reverse("hidp_otp_management:recovery-codes"))
        self.assertRedirects(response, reverse("hidp_otp_management:recovery-codes"))
        new_tokens = set(device.token_set.values_list("token", flat=True))
        self.assertEqual(new_tokens & current_tokens, set())
        self.assertEqual(len(new_tokens), 10)
