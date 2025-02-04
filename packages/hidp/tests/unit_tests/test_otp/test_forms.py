from django.test import TestCase

from hidp.otp.exceptions import MultipleOtpDevicesError, NoOtpDeviceError
from hidp.otp.forms import VerifyTOTPForm
from hidp.test.factories import otp_factories, user_factories


class OTPVerifyFormTest(TestCase):
    def test_clean_no_device(self):
        user = user_factories.UserFactory()
        form = VerifyTOTPForm(user)
        form.cleaned_data = {
            "otp_token": "123456",
        }
        with self.assertRaises(NoOtpDeviceError):
            form.clean()

    def test_clean_with_device(self):
        user = user_factories.UserFactory()
        otp_factories.TOTPDeviceFactory(user=user, confirmed=True)
        form = VerifyTOTPForm(user)
        form.cleaned_data = {
            "otp_token": "123456",
        }

        # No exception should be raised
        self.assertFalse(form.is_valid(), "Expected form to be invalid")

    def test_clean_with_multiple_devices(self):
        user = user_factories.UserFactory()
        otp_factories.TOTPDeviceFactory.create_batch(2, user=user, confirmed=True)
        form = VerifyTOTPForm(user)
        form.cleaned_data = {
            "otp_token": "123456",
        }
        with self.assertRaises(MultipleOtpDevicesError):
            form.clean()
