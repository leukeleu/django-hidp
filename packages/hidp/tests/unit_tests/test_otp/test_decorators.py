from unittest import TestCase

from django.http import HttpResponse

from hidp.otp.decorators import otp_exempt


@otp_exempt
def no_otp_required_for_this_view(request):
    return HttpResponse("No OTP required for this view.")


class TestOTPExemptDecorator(TestCase):
    def test_otp_exempt_decorator(self):
        self.assertTrue(
            hasattr(no_otp_required_for_this_view, "otp_exempt"),
            msg="Expected the view to have an `otp_exempt` attribute.",
        )
        self.assertTrue(
            no_otp_required_for_this_view.otp_exempt,
            msg="Expected the view to be exempt from OTP verification.",
        )
