from urllib.parse import urlencode

from django_ratelimit.decorators import ratelimit

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.db.models.functions import MD5
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views import generic
from django.views.decorators.cache import never_cache

from ..config import oidc_clients
from ..rate_limit.decorators import rate_limit_default, rate_limit_strict
from . import auth as hidp_auth
from . import email_verification, forms, mailer, tokens

UserModel = get_user_model()


class OIDCLoginContextMixin:
    """
    Mixin to provide context data for OIDC login providers.
    """

    def get_context_data(self, **kwargs):
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
            **kwargs,
        )


@method_decorator(ratelimit(key="ip", rate="2/s", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="5/m", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="30/15m", method="POST"), name="post")
class RegistrationView(
    auth_views.RedirectURLMixin, OIDCLoginContextMixin, generic.FormView
):
    """
    Display the registration form and handle the registration action.

    If the form is submitted with valid data, a new user account will be created
    and the user will be redirected to a page informing them that they must verify
    their email address.

    Otherwise, the form will be displayed with an error message explaining the
    reason for the failure and the user can try again.
    """

    form_class = forms.UserCreationForm
    template_name = "hidp/accounts/register.html"
    next_page = "/"
    verification_mailer = mailer.EmailVerificationMailer
    account_exists_mailer = mailer.AccountExistsMailer

    def get_context_data(self, **kwargs):
        login_url = resolve_url(settings.LOGIN_URL) + (
            f"?{urlencode({'next': redirect_url})}"
            if (redirect_url := self.get_redirect_url())
            else ""
        )
        return super().get_context_data(
            login_url=login_url,
            # Make sure logging out will return to the current page,
            # including the query string.
            logout_next_url=self.request.get_full_path(),
            **kwargs,
        )

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            raise PermissionDenied("Logged-in users cannot register a new account.")
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        """
        Save the new user and redirect to the email verification required page.
        """
        try:
            user = form.save()
        except IntegrityError:
            # The user exists! Find the user by the email address (case-insensitive).
            user = UserModel.objects.get(email__iexact=form.cleaned_data["email"])

        if not user.email_verified:
            # Send the email verification email.
            self.verification_mailer(
                user,
                base_url=self.request.build_absolute_uri("/"),
                post_verification_redirect=self.get_redirect_url(),
            ).send()
        else:
            # Email the user to inform them that they have an account.
            self.account_exists_mailer(
                user,
                base_url=self.request.build_absolute_uri("/"),
            ).send()

        # Always redirect to the email verification required page.
        # This is a security measure to prevent user enumeration.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


class TermsOfServiceView(generic.TemplateView):
    """
    Display the terms of service.
    """

    template_name = "hidp/accounts/tos.html"


@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(never_cache, name="dispatch")
class EmailVerificationRequiredView(auth_views.RedirectURLMixin, generic.TemplateView):
    """
    Display a notice that the user must verify their email address by
    clicking a link in an email that was sent to them.

    The page also includes the option to request a new verification email.
    """

    template_name = "hidp/accounts/verification/email_verification_required.html"
    token_generator = tokens.email_verification_request_token_generator
    verification_mailer = mailer.EmailVerificationMailer
    token_session_key = "_email_verification_request_token"  # noqa: S105 (not a password)
    token_placeholder = "email"  # noqa: S105 (not a password)

    def dispatch(self, request, *, token):
        if token == self.token_placeholder:
            token = self.request.session.get(self.token_session_key)
        else:
            # Store the token in the session and redirect to the
            # URL with a placeholder value.
            self.request.session[self.token_session_key] = token
            redirect_url = self.request.get_full_path().replace(
                token, self.token_placeholder
            )
            return HttpResponseRedirect(redirect_url, status=308)

        email_hash = self.token_generator.check_token(token)
        try:
            # Find the user by the hash of their email address
            self.user = UserModel.objects.annotate(email_hash=MD5("email")).get(
                email_hash=email_hash
            )
            self.validlink = True
        except UserModel.DoesNotExist:
            self.validlink = False
            self.user = None
        return super().dispatch(request, token=token)

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            validlink=self.validlink,
            **kwargs,
        )

    def post(self, *args, **kwargs):
        if self.validlink:
            # Send the email verification email.
            self.verification_mailer(
                self.user,
                base_url=self.request.build_absolute_uri("/"),
                post_verification_redirect=self.get_redirect_url(),
            ).send()
            # Redirect to the email verification required page, with a new token.
            return HttpResponseRedirect(
                email_verification.get_email_verification_required_url(
                    self.user, next_url=self.get_redirect_url()
                )
            )
        # Invalid token, do nothing and redirect to the same page.
        return HttpResponseRedirect(self.request.get_full_path())


@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(never_cache, name="dispatch")
class EmailVerificationView(auth_views.RedirectURLMixin, generic.FormView):
    """
    Landing page for email verification links.

    Contains a form that must be submitted to complete the verification process.
    """

    form_class = forms.EmailVerificationForm
    template_name = "hidp/accounts/verification/verify_email.html"
    token_generator = tokens.email_verification_token_generator
    success_url = reverse_lazy("hidp_accounts:email_verification_complete")
    token_session_key = "_email_verification_request_token"  # noqa: S105 (not a password)
    token_placeholder = "email"  # noqa: S105 (not a password)

    def dispatch(self, request, *, token):
        if token == self.token_placeholder:
            token = self.request.session.get(self.token_session_key)
        else:
            # Store the token in the session and redirect to the
            # URL with a placeholder value.
            self.request.session[self.token_session_key] = token
            redirect_url = self.request.get_full_path().replace(
                token, self.token_placeholder
            )
            return HttpResponseRedirect(redirect_url, status=308)

        email_hash = self.token_generator.check_token(token)
        try:
            # Find the user by the hash of their email address
            self.user = (
                UserModel.objects.annotate(email_hash=MD5("email"))
                .filter(is_active=True, email_verified__isnull=True)
                .get(email_hash=email_hash)
            )
            self.validlink = True
        except UserModel.DoesNotExist:
            self.validlink = False
            self.user = None
        return super().dispatch(request, token=token)

    def get_form_kwargs(self):
        return {
            **super().get_form_kwargs(),
            "user": self.user,
        }

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            validlink=self.validlink,
            **kwargs,
        )

    def form_valid(self, form):
        form.save()
        return HttpResponseRedirect(
            str(self.success_url)
            + (
                f"?{urlencode({'next': redirect_url})}"
                if (redirect_url := self.get_redirect_url())
                else ""
            )
        )


class EmailVerificationCompleteView(auth_views.RedirectURLMixin, generic.TemplateView):
    """
    Display a message that the email address has been verified.
    """

    template_name = "hidp/accounts/verification/email_verification_complete.html"

    def get_context_data(self, **kwargs):
        login_url = resolve_url(settings.LOGIN_URL) + (
            f"?{urlencode({'next': redirect_url})}"
            if (redirect_url := self.get_redirect_url())
            else ""
        )
        return super().get_context_data(
            login_url=login_url,
            **kwargs,
        )


@method_decorator(
    ratelimit(key="post:username", rate="10/m", method="POST", block=False), name="post"
)
@method_decorator(rate_limit_strict, name="dispatch")
class LoginView(OIDCLoginContextMixin, auth_views.LoginView):
    """
    Display the login form and handle the login action.

    If the form is submitted with valid credentials, the user will be logged in
    and redirected to the location returned by get_success_url().

    Otherwise, the form will be displayed with an error message explaining the
    reason for the failure and the user can try again.
    """

    # The form class to use for authentication
    form_class = forms.AuthenticationForm

    # The form class to use when the user is rate limited
    rate_limited_form_class = forms.RateLimitedAuthenticationForm

    # The template to use for displaying the login form
    template_name = "hidp/accounts/login.html"

    # If the user is already authenticated, redirect to the success URL
    # instead of displaying the login form.
    redirect_authenticated_user = False

    # Mailer class to use when a user's email address is not verified
    verification_mailer = mailer.EmailVerificationMailer

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
        register_url = reverse("hidp_accounts:register") + (
            f"?{urlencode({'next': redirect_url})}"
            if (redirect_url := self.get_redirect_url())
            else ""
        )
        return super().get_context_data(
            messages=messages.get_messages(self.request),
            register_url=register_url,
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

    def get_form_class(self):
        """
        Determine the form class to use for the view.
        If the request is rate limited, return a form that requires the user to prove
        they are not a bot.
        Otherwise, return the normal authentication form.
        """

        if self.request.limited:
            return self.rate_limited_form_class
        return super().get_form_class()

    def form_valid(self, form):
        """
        User has provided valid credentials and is allowed to log in.

        Persist the user and backend in the session and redirect to the
        success URL.

        If the user's email address has not been verified, redirect them
        to the email verification required flow.
        """
        user = form.get_user()
        if user.email_verified:
            # Only log in the user if their email address has been verified.
            hidp_auth.login(self.request, user)
            return HttpResponseRedirect(self.get_success_url())

        # If the user's email address is not yet verified:
        # Send the email verification email.
        self.verification_mailer(
            user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

        # Then redirect them to the email verification required page.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


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


@method_decorator(rate_limit_strict, name="dispatch")
class PasswordResetRequestView(generic.FormView):
    """
    Display the password reset request form and handle the password
    reset request action.

    Sends the password reset email and redirects to the password reset
    sent view if the form is submitted with valid data.
    """

    form_class = forms.PasswordResetRequestForm
    template_name = "hidp/accounts/recovery/password_reset_request.html"
    success_url = reverse_lazy("hidp_accounts:password_reset_email_sent")
    password_reset_request_mailer = mailer.PasswordResetRequestMailer

    def form_valid(self, form):
        if user := form.get_user():
            self.password_reset_request_mailer(
                user=user,
                base_url=self.request.build_absolute_uri("/"),
            ).send()
        return super().form_valid(form)


class PasswordResetEmailSentView(generic.TemplateView):
    """
    Display a message that the password reset email has been sent.
    """

    template_name = "hidp/accounts/recovery/password_reset_email_sent.html"


@method_decorator(rate_limit_default, name="dispatch")
class PasswordResetView(auth_views.PasswordResetConfirmView):
    """
    Display the password reset form and handle the password reset action.
    """

    form_class = forms.PasswordResetForm
    template_name = "hidp/accounts/recovery/password_reset.html"
    success_url = reverse_lazy("hidp_accounts:password_reset_complete")


class PasswordResetCompleteView(auth_views.TemplateView):
    """
    Display a message that the password reset has been completed.
    """

    template_name = "hidp/accounts/recovery/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            login_url=resolve_url(settings.LOGIN_URL),
            **kwargs,
        )
