from django.test import TestCase

from hidp.otp.forms import OTPVerifyFormBase
from hidp.test.factories import user_factories


class MissingDeviceForm(OTPVerifyFormBase):
    def get_device(self, user):
        return None


class OTPVerifyFormTest(TestCase):
    def test_clean_no_device(self):
        user = user_factories.UserFactory()
        form = MissingDeviceForm(user)
        form.cleaned_data = {
            "otp_token": "123456",
        }
        with self.assertRaises(RuntimeError) as cm:
            form.clean()
        self.assertEqual(
            str(cm.exception),
            "No device found for user. Ensure get_device() returns a device.",
        )
