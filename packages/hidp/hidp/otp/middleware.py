from abc import ABC, abstractmethod
from urllib.parse import urlencode

from django_otp import user_has_device

from django.shortcuts import redirect
from django.urls import reverse


class OTPMiddlewareBase(ABC):
    """
    Base class for OTP middleware.

    This class provides a base implementation for OTP middleware. It provides a
    `process_view` method that checks whether a request needs to verify OTP and
    redirects to the OTP verification view if necessary. The conditions on when
    to require verification must be implemented in the `user_needs_verification`
    method in a subclass. For more complex verification logic, you can override
    the `request_needs_verification` and `view_func_needs_verification` methods.

    Views can be marked as exempt from OTP verification by using the `otp_exempt`
    decorator.

    Middleware implementations should be placed after the authentication middleware
    and django_otp.middleware.OTPMiddleware. If `request_needs_verification`,
    it will redirect users to the OTP verification view if they have a configured OTP
    device, or else to the OTP setup view.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def _view_is_exempt(self, view_func):  # noqa: PLR6301
        """
        Check if a view function is exempt from OTP verification.

        A view is exempt if it has the `otp_exempt` attribute set to `True` by the
        `otp_exempt` decorator.
        """
        return getattr(view_func, "otp_exempt", False)

    def get_redirect_url(self, request):  # noqa: PLR6301
        """Return the URL to redirect to when OTP verification is required."""
        params = {"next": request.get_full_path()}
        return f"{reverse('hidp_otp:verify')}?{urlencode(params)}"

    @abstractmethod
    def user_needs_verification(self, user):
        """
        Check if a user needs to verify their OTP.

        Override this method to implement the verification logic.
        """

    def view_func_needs_verification(self, view_func):
        """
        Check whether a view function needs to verify OTP.

        Override this method if you need to customize the verification logic.
        """
        return not self._view_is_exempt(view_func)

    def request_needs_verification(self, request, view_func):
        """
        Check whether a request needs to verify OTP.

        The request needs to verify OTP if the user needs verification and the
        view function needs verification.
        """
        return self.view_func_needs_verification(
            view_func
        ) and self.user_needs_verification(request.user)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if self.request_needs_verification(request, view_func):
            return redirect(self.get_redirect_url(request))

        return None


class OTPRequiredIfConfiguredMiddleware(OTPMiddlewareBase):
    """
    Middleware that requires users to verify their OTP if they have OTP configured.

    This middleware should be placed after the authentication middleware and
    django_otp.middleware.OTPMiddleware. It will redirect users to the OTP
    verification view if they are authenticated, have a configured OTP device,
    but have not yet verified their OTP, or to the OTP setup view if they have not
    yet configured an OTP device.
    """

    def user_needs_verification(self, user):  # noqa: PLR6301
        """
        Check if a user needs to verify their OTP.

        A user needs to verify their OTP if they are authenticated, have an OTP
        device, and have not yet verified their OTP.
        """
        return (
            user.is_authenticated and not user.is_verified() and user_has_device(user)
        )


class OTPRequiredIfStaffUserMiddleware(OTPMiddlewareBase):
    """
    Middleware that requires staff users to verify their OTP.

    This middleware should be placed after the authentication middleware and
    django_otp.middleware.OTPMiddleware. It will redirect staff users to the OTP
    verification view if they are authenticated and are staff, even if they do not
    have an OTP device configured. If they don't have an OTP device configured, they
    will be redirected to the OTP setup view.
    """

    def user_needs_verification(self, user):  # noqa: PLR6301
        """
        Check if a user needs to verify their OTP.

        A user needs to verify their OTP if they are authenticated, are staff, and
        have not yet verified their OTP.
        """
        return user.is_authenticated and user.is_staff and not user.is_verified()

    def get_redirect_url(self, request):  # noqa: PLR6301
        """
        Return the URL to redirect to when OTP verification is required.

        If the user has an OTP device, they will be redirected to the OTP verification
        view. If they do not have an OTP device, they will be redirected to the OTP
        setup view.
        """
        next_url = request.get_full_path()
        target = (
            reverse("hidp_otp:verify")
            if user_has_device(request.user)
            else reverse("hidp_otp_management:setup")
        )
        return target + f"?{urlencode({'next': next_url})}"
