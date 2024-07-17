from django_ratelimit.decorators import ratelimit

from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import generic

from hidp.rate_limit.decorators import rate_limit_default, rate_limit_strict

from ..config import oidc_clients
from . import auth as hidp_auth
from .forms import AuthenticationForm, UserCreationForm


@method_decorator(ratelimit(key="ip", rate="2/s", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="5/m", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="30/15m", method="POST"), name="post")
class RegistrationView(auth_views.RedirectURLMixin, generic.FormView):
    """
    Display the registration form and handle the registration action.

    If the form is submitted with valid data, a new user account will be created
    and the user will be logged in and redirected to the location returned
    by get_success_url().

    Otherwise, the form will be displayed with an error message explaining the
    reason for the failure and the user can try again.
    """

    form_class = UserCreationForm
    template_name = "accounts/register.html"
    next_page = "/"

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            raise PermissionDenied("Logged-in users cannot register a new account.")
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        """
        Save the new user and log them in.
        """
        user = form.save()
        hidp_auth.login(
            self.request,
            hidp_auth.authenticate(
                request=self.request,
                username=user.get_username(),
                password=form.cleaned_data["password1"],
            ),
        )
        return HttpResponseRedirect(self.get_success_url())


@method_decorator(
    ratelimit(key="post:username", rate="10/m", method="POST"), name="post"
)
@method_decorator(rate_limit_strict, name="dispatch")
class LoginView(auth_views.LoginView):
    """
    Display the login form and handle the login action.

    If the form is submitted with valid credentials, the user will be logged in
    and redirected to the location returned by get_success_url().

    Otherwise, the form will be displayed with an error message explaining the
    reason for the failure and the user can try again.
    """

    # The form class to use for authentication
    form_class = AuthenticationForm
    # The template to use for displaying the login form
    template_name = "accounts/login.html"

    # If the user is already authenticated, redirect to the success URL
    # instead of displaying the login form.
    redirect_authenticated_user = False

    def get_context_data(self, **kwargs):
        """
        Additional context data for the login template.

        By default, the context data includes:

        * `view`: The current view instance
        * `form`: The login form
        * `self.redirect_field_name` (i.e. `next`):
          The URL to redirect to after login (if present in the request)
        * `site`:
          The current site instance
          (`RequestSite` if `django.contrib.sites` is not installed)
        * `site_name`:
          The name of the current site (host name if `RequestSite` is used)
        * Any additional data present is `self.extra_context`
        """
        return super().get_context_data(
            oidc_login_providers=[
                {
                    "provider": provider,
                    "url": reverse(
                        "hidp_oidc_client:authenticate",
                        kwargs={
                            "provider_key": provider.provider_key,
                        },
                    ),
                }
                for provider in oidc_clients.get_registered_oidc_clients()
            ],
            messages=messages.get_messages(self.request),
            **kwargs,
        )

    def get_success_url(self):
        """
        Return the URL to redirect to after a successful login.

        Returns one of the following:

        1. The URL specified by the `self.redirect_field_name`
          (i.e. `next`) parameter, if it is present in the request and
          the value is valid and safe.
        2. The URL specified by `self.next_page` if it is set.
        3. `settings.LOGIN_REDIRECT_URL` if it is set.
        """
        return super().get_success_url()

    def form_valid(self, form):
        """
        User has provided valid credentials and is allowed to log in.
        Persist the user and backend in the session and redirect to the
        success URL.
        """
        # This **replaces** the base implementation in order to use the
        # HIdP login wrapper function, that performs additional checks.
        hidp_auth.login(self.request, form.get_user())
        return HttpResponseRedirect(self.get_success_url())


@method_decorator(rate_limit_default, name="dispatch")
class LogoutView(auth_views.LogoutView):
    """
    Logs out the user, regardless of whether a user is logged in.

    A POST request (including a CSRF token) is required to log out.
    This prevents a malicious site from logging out a user without their consent,
    for example by linking to the logout URL.

    After logging out, the user is redirected to the URL returned by get_redirect_url().
    """

    # Django 5.0 will no longer allow GET (and HEAD) requests to the logout view.
    # Disallow these methods now for forward compatibility.
    http_method_names = [
        method
        for method in auth_views.LogoutView.http_method_names
        if method not in {"get", "head"}
    ]

    def get_redirect_url(self):
        """
        Return the URL to redirect to after a successful logout.

        Returns one of the following:

        1. The URL specified by the `self.redirect_field_name`
          (i.e. `next`) parameter, if it is present in the request and
          the value is valid and safe.
        2. The URL specified by `self.next_page` if it is set.
        3. `settings.LOGOUT_REDIRECT_URL` if it is set.
        """
        return super().get_redirect_url()

    def post(self, request, *args, **kwargs):
        """
        Log out the user and redirect to the success URL.
        """
        # This **replaces** the base implementation in order to use the
        # HIdP logout wrapper, for good measure.
        hidp_auth.logout(request)
        redirect_to = self.get_success_url()
        if redirect_to != request.get_full_path():
            # Redirect to target page once the session has been cleared.
            return HttpResponseRedirect(redirect_to)
        return super().get(request, *args, **kwargs)
