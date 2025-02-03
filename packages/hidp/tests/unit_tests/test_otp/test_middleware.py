from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from hidp.otp.decorators import otp_exempt
from hidp.otp.middleware import (
    OTPSetupRequiredIfStaffUserMiddleware,
    OTPVerificationRequiredIfConfiguredMiddleware,
)
from hidp.test.factories import otp_factories, user_factories


class OTPMiddlewareTestBase(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()

    @staticmethod
    def verify_user(user, *, verified):
        user.is_verified = lambda: verified

    def assertMiddlewareRedirects(self, response, expected_url, message=None):  # noqa: N802
        """
        Replacement for self.assertRedirects that works without the test client.

        The result of a middleware process_view call is a redirect response, but we
        cannot use the test client to check the response. This method checks the
        response manually. Additionally, the result of process_view may be None if
        the middleware does not redirect, so we need to check for that as well.
        """
        self.assertIsNotNone(response, "Expected a redirect response.")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, expected_url, message)


def basic_view(request):
    return HttpResponse("Hello, world!")


@otp_exempt
def exempt_view(request):
    return HttpResponse("I'm exempt from OTP verification.")


class TestOTPRequiredIfConfiguredMiddleware(OTPMiddlewareTestBase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()
        cls.confirmed_user = user_factories.VerifiedUserFactory()
        otp_factories.TOTPDeviceFactory(user=cls.confirmed_user, confirmed=True)
        otp_factories.StaticDeviceFactory(user=cls.confirmed_user, confirmed=True)

        cls.middleware = OTPVerificationRequiredIfConfiguredMiddleware(
            lambda request: None
        )

    def setUp(self):
        super().setUp()

        # The middleware expects the OTPMiddleware to have already run, so we need to
        # manually set the user's verified property.
        self.verify_user(self.user, verified=False)
        self.verify_user(self.confirmed_user, verified=False)

    def test_anonymous_user(self):
        """Anonymous users should not need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = AnonymousUser()

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected anonymous users to not need to verify OTP.",
        )

    def test_user_without_otp(self):
        """Users without OTP devices should not need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = self.user

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected users without OTP devices to not need to verify OTP.",
        )

    def test_user_with_unconfirmed_otp(self):
        """Users with unconfirmed OTP devices should not need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = self.user
        otp_factories.TOTPDeviceFactory(user=self.user, confirmed=False)

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected users with unconfirmed OTP devices to not need to verify"
            " OTP.",
        )

    def test_user_with_confirmed_otp(self):
        """Users with confirmed OTP devices should need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = self.confirmed_user

        self.assertTrue(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected users with confirmed OTP devices to need to verify OTP.",
        )

    def test_verified_user(self):
        """Users who have already verified their OTP should not need to verify again."""
        request = self.request_factory.get("/")
        request.user = self.confirmed_user
        self.verify_user(request.user, verified=True)

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected users who have already verified their OTP to not need to "
            "verify again.",
        )

    def test_exempt_view(self):
        """Views marked as exempt should not require verification."""
        request = self.request_factory.get("/")
        request.user = self.confirmed_user

        self.assertFalse(
            self.middleware.request_needs_verification(request, exempt_view),
            msg="Expected exempt views to not require OTP verification.",
        )

    def test_process_view_redirects(self):
        """The middleware should redirect to the OTP verification view if required."""
        request = self.request_factory.get("/some-path/")
        request.user = self.confirmed_user

        response = self.middleware.process_view(request, basic_view, [], {})
        self.assertMiddlewareRedirects(
            response,
            "/otp/verify/?next=%2Fsome-path%2F",
            "Expected redirect to OTP verification view.",
        )

    def test_process_view_does_not_redirect(self):
        """The middleware should not redirect if verification is not required."""
        request = self.request_factory.get("/")
        request.user = AnonymousUser()

        response = self.middleware.process_view(request, basic_view, [], {})

        self.assertIsNone(response)

    def test_best_case_requires_no_queries(self):
        """The middleware should require no queries in the best case."""
        request = self.request_factory.get("/")
        request.user = self.confirmed_user
        self.verify_user(request.user, verified=True)

        with self.assertNumQueries(0):
            self.middleware.process_view(request, basic_view, [], {})


class TestOTPRequiredIfStaffUser(OTPMiddlewareTestBase):
    @classmethod
    def setUpTestData(cls):
        cls.middleware = OTPSetupRequiredIfStaffUserMiddleware(lambda request: None)
        cls.unconfirmed_staff_user = user_factories.VerifiedUserFactory(is_staff=True)
        cls.verify_user(cls.unconfirmed_staff_user, verified=False)

        cls.confirmed_staff_user = user_factories.VerifiedUserFactory(is_staff=True)
        otp_factories.TOTPDeviceFactory(user=cls.confirmed_staff_user, confirmed=True)
        cls.verify_user(cls.confirmed_staff_user, verified=False)

    def test_anonymous_user(self):
        """Anonymous users should not need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = AnonymousUser()

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected anonymous users to not need to verify OTP.",
        )

    def test_non_staff_user(self):
        """Non-staff users should not need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = user_factories.VerifiedUserFactory(is_staff=False)

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected non-staff users to not need to verify OTP.",
        )

    def test_staff_user(self):
        """Staff users should need to verify OTP."""
        request = self.request_factory.get("/")
        request.user = self.unconfirmed_staff_user

        self.assertTrue(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected staff users to need to verify OTP.",
        )

    def test_verified_staff_user(self):
        """Staff users who have already verified their OTP should not need to verify."""
        request = self.request_factory.get("/")
        request.user = self.confirmed_staff_user
        self.verify_user(request.user, verified=True)

        self.assertFalse(
            self.middleware.request_needs_verification(request, basic_view),
            msg="Expected staff users who have already verified their OTP to not need "
            "to verify again.",
        )

    def test_staff_user_exempt_view(self):
        """Staff users should not need to verify OTP for exempt views."""
        request = self.request_factory.get("/")
        request.user = self.unconfirmed_staff_user

        self.assertFalse(
            self.middleware.request_needs_verification(request, exempt_view),
            msg="Expected staff users to not need to verify OTP for exempt views.",
        )

    def test_redirects_to_otp_verify(self):
        """The middleware should redirect to the OTP verification view if required."""
        request = self.request_factory.get("/some-path/")
        request.user = self.confirmed_staff_user

        response = self.middleware.process_view(request, basic_view, [], {})

        self.assertMiddlewareRedirects(
            response,
            "/otp/verify/?next=%2Fsome-path%2F",
            "Expected redirect to OTP verification view.",
        )

    def test_redirects_to_setup_view(self):
        """Middleware should redirect to the OTP setup view if the user has no OTP."""
        request = self.request_factory.get("/some-path/")
        request.user = self.unconfirmed_staff_user

        response = self.middleware.process_view(request, basic_view, [], {})

        self.assertMiddlewareRedirects(
            response,
            "/manage/otp/setup/?next=%2Fsome-path%2F",
            "Expected redirect to OTP setup view.",
        )
