from http import HTTPStatus
from unittest import mock

from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from hidp.otp.devices import reset_static_tokens
from hidp.otp.forms import VerifyTOTPForm
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

    @mock.patch.object(VerifyTOTPForm, "clean_otp", return_value=None, autospec=True)
    def test_post_otp_disable(self, mock_clean_otp):
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        static_device = otp_factories.StaticDeviceFactory(
            user=self.user, confirmed=True
        )
        otp_factories.StaticTokenFactory.create_batch(10, device=static_device)
        self.client.force_login(self.user)

        form_data = {
            "otp_token": "123456",
        }
        response = self.client.post(reverse("hidp_otp_management:disable"), form_data)
        self.assertRedirects(response, reverse("hidp_otp_management:manage"))
        self.assertFalse(
            self.user.totpdevice_set.exists(),
            msg="Expected the user to have no TOTP devices",
        )
        self.assertFalse(
            self.user.staticdevice_set.exists(),
            msg="Expected the user to have no static devices",
        )

    def test_static_token_not_accepted(self):
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        static_device = otp_factories.StaticDeviceFactory(
            user=self.user, confirmed=True
        )
        otp_factories.StaticTokenFactory.create_batch(9, device=static_device)
        otp_factories.StaticTokenFactory(token="static-token", device=static_device)
        self.client.force_login(self.user)

        form_data = {
            "otp_token": "static-token",
        }
        response = self.client.post(reverse("hidp_otp_management:disable"), form_data)
        form = response.context["form"]
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid")
        # Check that the error is on the token field
        errors = form.errors.as_data()
        self.assertEqual(errors["__all__"][0].code, "invalid_token")
        self.assertTrue(
            self.user.totpdevice_set.exists(),
            msg="Expected the user to have TOTP devices",
        )
        self.assertTrue(
            self.user.staticdevice_set.exists(),
            msg="Expected the user to have static devices",
        )


class TestOTPDisableWithRecoveryCode(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp_management:disable-recovery-code"))
        self.assertRedirects(
            response,
            f"/login/?next={reverse('hidp_otp_management:disable-recovery-code')}",
        )

    def test_get_otp_disable_with_recovery_code(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:disable-recovery-code"))
        self.assertTemplateUsed(response, "hidp/otp/disable_recovery_code.html")

    def test_post_otp_disable_with_recovery_code(self):
        static_device = otp_factories.StaticDeviceFactory(
            user=self.user, confirmed=True
        )
        otp_factories.StaticTokenFactory.create_batch(9, device=static_device)
        otp_factories.StaticTokenFactory(device=static_device, token="static-token")
        self.client.force_login(self.user)

        form_data = {
            "otp_token": "static-token",
        }
        with (
            self.assertTemplateUsed("hidp/otp/email/disabled_subject.txt"),
            self.assertTemplateUsed("hidp/otp/email/disabled_body.txt"),
            self.assertTemplateUsed("hidp/otp/email/disabled_body.html")
        ):  # fmt: skip
            response = self.client.post(
                reverse("hidp_otp_management:disable-recovery-code"), form_data
            )
        self.assertRedirects(response, reverse("hidp_otp_management:manage"))
        self.assertFalse(
            self.user.totpdevice_set.exists(),
            msg="Expected the user to have no TOTP devices",
        )
        self.assertFalse(
            self.user.staticdevice_set.exists(),
            msg="Expected the user to have no static devices",
        )

        self.assertEqual(len(mail.outbox), 1, "Expected an email to be sent")
        self.assertEqual(mail.outbox[0].subject, "Two-factor authentication disabled")
        self.assertEqual(mail.outbox[0].to, [self.user.email])


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
        with (
            self.assertTemplateUsed("hidp/otp/email/recovery_codes_regenerated_subject.txt"),
            self.assertTemplateUsed("hidp/otp/email/recovery_codes_regenerated_body.txt"),
            self.assertTemplateUsed("hidp/otp/email/recovery_codes_regenerated_body.html")
        ):  # fmt: skip
            response = self.client.post(reverse("hidp_otp_management:recovery-codes"))
        self.assertRedirects(response, reverse("hidp_otp_management:recovery-codes"))
        new_tokens = set(device.token_set.values_list("token", flat=True))
        self.assertEqual(new_tokens & current_tokens, set())
        self.assertEqual(len(new_tokens), 10)

        self.assertEqual(len(mail.outbox), 1, "Expected an email to be sent")
        self.assertEqual(mail.outbox[0].subject, "Recovery codes were regenerated")
        self.assertEqual(mail.outbox[0].to, [self.user.email])


class TestOTPSetupView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        """The user must be logged in to set up OTP."""
        response = self.client.get(reverse("hidp_otp_management:setup"))
        self.assertRedirects(
            response, f"/login/?next={reverse('hidp_otp_management:setup')}"
        )

    def test_redirects_to_manage_when_already_setup(self):
        """The user should be redirected to the manage page if OTP is already set up."""
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        response = self.client.get(reverse("hidp_otp_management:setup"))
        self.assertRedirects(response, reverse("hidp_otp_management:setup-device-done"))

    def test_redirects_to_next_page_when_already_setup(self):
        """The user should be redirected to the next page after setup."""
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        response = self.client.get(
            f"{reverse('hidp_otp_management:setup')}?next=/my-special-page/"
        )
        self.assertRedirects(
            response, "/my-special-page/", fetch_redirect_response=False
        )

    def test_valid_form_confirms_devices(self):
        """A valid form should confirm the TOTP and static devices."""
        self.client.force_login(self.user)
        device = otp_factories.TOTPDeviceFactory(user=self.user, confirmed=False)
        form_data = {
            "otp_token": "123456",
            "confirm_stored_backup_tokens": True,
        }
        with (
            mock.patch.object(device, "verify_token", return_value=True, autospec=True),
            mock.patch("hidp.otp.forms.OTPSetupForm.get_device", return_value=device),
            self.assertTemplateUsed("hidp/otp/email/configured_subject.txt"),
            self.assertTemplateUsed("hidp/otp/email/configured_body.txt"),
            self.assertTemplateUsed("hidp/otp/email/configured_body.html"),
        ):
            response = self.client.post(reverse("hidp_otp_management:setup"), form_data)
        self.assertRedirects(response, reverse("hidp_otp_management:setup-device-done"))

        totp_device = TOTPDevice.objects.get(user=self.user)
        self.assertTrue(totp_device.confirmed, "Expected TOTP device to be confirmed")

        static_device = StaticDevice.objects.get(user=self.user)
        self.assertTrue(
            static_device.confirmed, "Expected static device to be confirmed"
        )

        self.assertEqual(len(mail.outbox), 1, "Expected an email to be sent")
        self.assertEqual(mail.outbox[0].subject, "Two-factor authentication configured")
        self.assertEqual(mail.outbox[0].to, [self.user.email])

    def test_invalid_form_does_not_confirm_devices(self):
        """An invalid form should not confirm the TOTP and static devices."""
        self.client.force_login(self.user)
        form_data = {
            "otp_token": "invalid",
            "confirm_stored_backup_tokens": True,
        }
        response = self.client.post(reverse("hidp_otp_management:setup"), form_data)
        form = response.context["form"]
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid")
        # Check that the error is on the token field
        errors = form.errors.as_data()
        self.assertEqual(errors["__all__"][0].code, "invalid_token")

        totp_device = TOTPDevice.objects.get(user=self.user)
        self.assertFalse(
            totp_device.confirmed, "Expected TOTP device to be unconfirmed"
        )

        static_device = StaticDevice.objects.get(user=self.user)
        self.assertFalse(
            static_device.confirmed, "Expected static device to be unconfirmed"
        )

    def _setup_up_otp(self, *, next_page=None):
        self.client.force_login(self.user)
        self.assertFalse(
            TOTPDevice.objects.devices_for_user(self.user, confirmed=None).exists()
        )

        setup_url = reverse("hidp_otp_management:setup")
        if next_page:
            setup_url += f"?next={next_page}"

        response = self.client.get(setup_url)
        device = TOTPDevice.objects.devices_for_user(self.user, confirmed=None).get()
        self.assertFalse(
            response.wsgi_request.user.is_verified(), "Expected user to be unverified"
        )
        form_data = {
            "otp_token": "123456",
            "confirm_stored_backup_tokens": True,
        }
        with (
            mock.patch.object(device, "verify_token", return_value=True, autospec=True),
            mock.patch("hidp.otp.forms.OTPSetupForm.get_device", return_value=device),
        ):
            return self.client.post(setup_url, form_data)

    def test_setting_up_otp_verifies_user(self):
        """Setting up OTP successfully should verify the user."""
        response = self._setup_up_otp()
        self.assertRedirects(response, reverse("hidp_otp_management:setup-device-done"))
        self.assertTrue(
            response.wsgi_request.user.is_verified(), "Expected user to be verified"
        )

    def test_setting_up_otp_redirects_to_next_page(self):
        """Setting up OTP successfully should redirect to the next page."""
        response = self._setup_up_otp(next_page="/my-special-page/")
        self.assertRedirects(
            response, "/my-special-page/", fetch_redirect_response=False
        )


class TestOTPVerifyView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp:verify"))
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={reverse('hidp_otp:verify')}",
        )

    def test_valid_form_verifies_user(self):
        device = otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        form_data = {"otp_token": "123456"}
        manage_url = reverse("hidp_account_management:manage_account")
        with (
            mock.patch.object(device, "verify_token", return_value=True, autospec=True),
            mock.patch("hidp.otp.forms.VerifyTOTPForm.get_device", return_value=device),
        ):
            response = self.client.post(
                f"{reverse('hidp_otp:verify')}?next={manage_url}", form_data
            )
            self.assertRedirects(response, manage_url)
        self.assertTrue(
            response.wsgi_request.user.is_verified(), "Expected user to be verified"
        )

    def test_invalid_form_does_not_verify_user(self):
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=True)
        self.client.force_login(self.user)
        form_data = {"otp_token": "invalid"}
        response = self.client.post(reverse("hidp_otp:verify"), form_data)
        form = response.context["form"]
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid")
        # Check that the error is on the token field
        errors = form.errors.as_data()
        self.assertEqual(errors["__all__"][0].code, "invalid_token")
        self.assertFalse(
            response.wsgi_request.user.is_verified(), "Expected user to be unverified"
        )


class TestOTPVerifyWithRecoveryCodeView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_login(self):
        response = self.client.get(reverse("hidp_otp:verify-recovery-code"))
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={reverse('hidp_otp:verify-recovery-code')}",
        )

    def test_valid_form_verifies_user(self):
        device = otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        otp_factories.StaticTokenFactory(token="123456", device=device)
        self.client.force_login(self.user)
        form_data = {"otp_token": "123456"}
        manage_url = reverse("hidp_account_management:manage_account")
        with (
            self.assertTemplateUsed("hidp/otp/email/recovery_code_used_subject.txt"),
            self.assertTemplateUsed("hidp/otp/email/recovery_code_used_body.txt"),
            self.assertTemplateUsed("hidp/otp/email/recovery_code_used_body.html"),
        ):
            response = self.client.post(
                f"{reverse('hidp_otp:verify-recovery-code')}?next={manage_url}",
                form_data,
            )
        self.assertRedirects(response, manage_url)
        self.assertTrue(
            response.wsgi_request.user.is_verified(), "Expected user to be verified"
        )

        self.assertEqual(len(mail.outbox), 1, "Expected an email to be sent")
        self.assertEqual(mail.outbox[0].subject, "Recovery code used")
        self.assertEqual(mail.outbox[0].to, [self.user.email])

    def test_invalid_form_does_not_verify_user(self):
        device = otp_factories.StaticDeviceFactory(user=self.user, confirmed=True)
        otp_factories.StaticTokenFactory.create_batch(10, device=device)
        self.client.force_login(self.user)
        form_data = {"otp_token": "invalid"}
        response = self.client.post(reverse("hidp_otp:verify-recovery-code"), form_data)
        form = response.context["form"]
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid")
        # Check that the error is on the token field
        errors = form.errors.as_data()
        self.assertEqual(errors["__all__"][0].code, "invalid_token")
        self.assertFalse(
            response.wsgi_request.user.is_verified(), "Expected user to be unverified"
        )

        self.assertEqual(len(mail.outbox), 0, "Expected no email to be sent")
