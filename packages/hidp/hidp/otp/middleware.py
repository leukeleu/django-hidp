import functools

from http import HTTPStatus
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django_otp import user_has_device

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.cache import add_never_cache_headers
from django.utils.module_loading import import_string

from hidp.constants import Step
from hidp.utils import get_frontend_url, has_frontend_url, is_api_view


class OTPMiddlewareBase:
    """
    Base class for OTP middleware.

    This class provides a base implementation for OTP middleware. It provides a
    ``process_view`` method that checks whether a request needs to verify OTP and
    redirects to the OTP verification view if necessary. The conditions on when to
    require verification can be implemented by overriding the
    ``user_needs_verification`` method in a subclass. For more complex verification
    logic, you can override the ``request_needs_verification`` and
    ``view_func_needs_verification`` methods.

    Views can be marked as exempt from OTP verification by using the ``otp_exempt``
    decorator.

    Middleware implementations should be placed after the authentication middleware
    and ``django_otp.middleware.OTPMiddleware``. If ``request_needs_verification``,
    it will redirect users to the OTP verification view if they have a configured OTP
    device, or else to the OTP setup view. Django REST framework views get a 401
    response with the authentication state instead.
    """

    def __new__(cls, *args, **kwargs):
        if cls is OTPMiddlewareBase:
            raise TypeError(
                f"{cls.__name__} cannot be used directly, use one of the "
                "subclasses instead"
            )
        return super().__new__(cls)

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

    def get_pending_step(self, request):  # noqa: PLR6301
        """Return `otp_verify` for a user with an OTP device, else `otp_setup`."""
        return Step.OTP_VERIFY if user_has_device(request.user) else Step.OTP_SETUP

    def get_redirect_url(self, request):
        """
        Return the URL to redirect to when OTP verification is required.

        If the user has an OTP device, they will be redirected to the OTP verification
        view. If they do not have an OTP device, they will be redirected to the OTP
        setup view. The `otp_verify` and `otp_setup` keys of `HIDP_FRONTEND_URLS`
        take the place of these views when set.

        Args:
            request (``HttpRequest``): The request object.

        Returns:
            str: The URL to redirect to.
        """
        step = self.get_pending_step(request)
        if has_frontend_url(step):
            target = get_frontend_url(step, base_url=request.build_absolute_uri("/"))
        else:
            target = reverse(
                "hidp_otp:verify"
                if step == Step.OTP_VERIFY
                else "hidp_otp_management:setup"
            )
        scheme, netloc, path, query, fragment = urlsplit(target)
        query = urlencode(
            [
                *parse_qsl(query, keep_blank_values=True),
                ("next", request.get_full_path()),
            ]
        )
        return urlunsplit((scheme, netloc, path, query, fragment))

    def get_api_response(self, request):
        """Return the 401 authentication state for a Django REST framework view."""
        response = JsonResponse(
            {"user": None, "pending": [{"step": self.get_pending_step(request)}]},
            status=HTTPStatus.UNAUTHORIZED,
        )
        add_never_cache_headers(response)
        return response

    def user_needs_verification(self, user):  # noqa: PLR6301
        """
        Check if a user needs to verify their OTP.

        By default, this will require all (authenticated and not verified) users to
        verify. Override this method to customize the verification logic.

        Args:
            user (``User``): The user to check.

        Returns:
            bool: Whether the user needs to verify their OTP.
        """
        return True

    def view_func_needs_verification(self, view_func):
        """
        Check whether a view function needs to verify OTP.

        Override this method if you need to customize the verification logic.

        Args:
            view_func (callable): The view function to check.

        Returns:
            bool: Whether the view function needs to verify OTP.
        """
        return not self._view_is_exempt(view_func)

    def request_needs_verification(self, request, view_func):
        """
        Check whether a request needs to verify OTP.

        The request needs to verify OTP if the user needs verification and the view
        function needs verification. The user never needs to verify if they are not
        authenticated or already verified.

        Args:
            request (``HttpRequest``): The request object.
            view_func (callable): The view function that will be called.

        Returns:
            bool: Whether the request requires the user to verify OTP.
        """
        return self.view_func_needs_verification(
            view_func
        ) and self.session_needs_verification(request)

    def session_needs_verification(self, request):
        """
        Check whether the user of a request needs to verify OTP, for any view.

        Args:
            request (``HttpRequest``): The request object.

        Returns:
            bool: Whether the user is authenticated, not verified and needs to be.
        """
        # A user logged in during this request has not been through OTPMiddleware.
        is_verified = getattr(request.user, "is_verified", None)
        return (
            request.user.is_authenticated
            and not (is_verified and is_verified())
            and self.user_needs_verification(request.user)
        )

    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Process a view and check if OTP verification is required.

        This method is called by the middleware to check if the user needs to verify
        their OTP. If verification is required, the user will be redirected to the OTP
        verification view, or to the OTP setup view if they do not have an OTP device.

        Args:
            request (``HttpRequest``): The request object.
            view_func (callable): The view function that will be called.
            view_args (list): The positional arguments passed to the view function.
            view_kwargs (dict): The keyword arguments passed to the view function.

        Returns:
            ``None`` or ``HttpResponseRedirect``: HttpResponseRedirect if this policy
            requires the user to verify OTP, None otherwise.
        """
        if self.request_needs_verification(request, view_func):
            if is_api_view(view_func):
                return self.get_api_response(request)
            return redirect(self.get_redirect_url(request))

        return None


class OTPRequiredMiddleware(OTPMiddlewareBase):
    """
    Middleware that requires all users to verify their OTP.

    This middleware should be placed after the authentication middleware and
    django_otp.middleware.OTPMiddleware. It will redirect users to the OTP
    verification view if they are authenticated and have not yet verified their OTP,
    or to the OTP setup view if they have not yet configured an OTP device.
    """


class OTPVerificationRequiredIfConfiguredMiddleware(OTPMiddlewareBase):
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
        return user_has_device(user)


class OTPSetupRequiredIfStaffUserMiddleware(OTPMiddlewareBase):
    """
    Middleware that requires staff users to configure and verify their OTP.

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
        return user.is_staff


@functools.cache
def _get_otp_middlewares(middleware):
    return tuple(
        middleware_class(lambda request: None)
        for middleware_class in map(import_string, middleware)
        if isinstance(middleware_class, type)
        and issubclass(middleware_class, OTPMiddlewareBase)
    )


def get_otp_middlewares():
    """Return an instance of every OTP middleware in `MIDDLEWARE`, in order."""
    return _get_otp_middlewares(tuple(settings.MIDDLEWARE))
