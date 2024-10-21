import logging

from datetime import timedelta
from urllib.parse import urlencode

from django_ratelimit.decorators import ratelimit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.db.models.functions import MD5
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import generic
from django.views.decorators.cache import never_cache

from ..config import oidc_clients
from ..csp.decorators import hidp_csp_protection
from ..federated.views import OIDCContextMixin
from ..rate_limit.decorators import rate_limit_default, rate_limit_strict
from . import auth as hidp_auth
from . import email_verification, forms, mailers, tokens
from .email_change import Recipient
from .models import EmailChangeRequest

logger = logging.getLogger(__name__)
UserModel = get_user_model()


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(ratelimit(key="ip", rate="2/s", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="5/m", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="30/15m", method="POST"), name="post")
class RegistrationView(auth_views.RedirectURLMixin, OIDCContextMixin, generic.FormView):
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
    verification_mailer = mailers.EmailVerificationMailer
    account_exists_mailer = mailers.AccountExistsMailer

    def get_context_data(self, **kwargs):
        login_url = resolve_url(settings.LOGIN_URL) + (
            f"?{urlencode({'next': redirect_url})}"
            if (redirect_url := self.get_redirect_url())
            else ""
        )
        context = {
            "user": self.request.user,
            "login_url": login_url,
            "next": self.get_success_url(),
            "logout_url": reverse("hidp_accounts:logout"),
            "logout_next_url": self.request.get_full_path(),
            "can_register": not self.request.user.is_authenticated,
        }
        return super().get_context_data() | context | kwargs

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            raise PermissionDenied("Logged-in users cannot register a new account.")
        return super().post(request, *args, **kwargs)

    def send_email(self, user):
        """Send the appropriate email to the user."""
        base_url = self.request.build_absolute_uri("/")
        if not user.email_verified:
            # Send the email verification email.
            self.verification_mailer(
                user,
                base_url=base_url,
                post_verification_redirect=self.get_redirect_url(),
            ).send()
        else:
            # Email the user to inform them that they have an account.
            self.account_exists_mailer(
                user,
                base_url=base_url,
            ).send()

    def form_valid(self, form):
        """Save the new user and redirect to the email verification required page."""
        try:
            user = form.save()
        except IntegrityError:
            # The user exists! Find the user by the email address (case-insensitive).
            user = UserModel.objects.get(email__iexact=form.cleaned_data["email"])

        self.send_email(user)

        # Always redirect to the email verification required page.
        # This is a security measure to prevent user enumeration.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


@method_decorator(hidp_csp_protection, name="dispatch")
class TermsOfServiceView(generic.TemplateView):
    """Display the terms of service."""

    template_name = "hidp/accounts/tos.html"


class BaseTokenMixin:
    """Mixin to handle tokens in URLs."""

    token_generator = NotImplemented
    token_session_key = NotImplemented
    token_placeholder = "token"  # noqa: S105 (not a password)

    def _remove_token_from_url(self, token):
        """
        Move the token from the URL to the session and redirect to the placeholder URL.

        If the url already is the placeholder URL, do nothing.
        """
        if token == self.token_placeholder:
            # Token is already the placeholder value, so do nothing.
            return None
        # Store the token in the session and redirect to the
        # URL with a placeholder value.
        self.request.session[self.token_session_key] = token
        redirect_url = self.request.get_full_path().replace(
            token, self.token_placeholder
        )
        return HttpResponseRedirect(redirect_url, status=308)


class EmailTokenMixin(BaseTokenMixin):
    """Mixin to handle email verification tokens in URLs."""

    token_placeholder = "email"  # noqa: S105 (not a password)

    def _get_user_queryset(self):  # noqa: PLR6301 (no-self-use)
        """
        Base queryset for finding the user by the token.

        Override this method to customize the queryset, i.e. to
        add additional filters or annotations.
        """
        return UserModel.objects.annotate(email_hash=MD5("email"))

    def _get_user_from_token(self):
        """
        Find the user associated with the token in the session.

        Returns:
            UserModel | None:
                The user if the token is valid, otherwise None.
        """
        token = self.request.session.get(self.token_session_key)
        if token is None:
            return None
        email_hash = self.token_generator.check_token(token)
        # Find the user by the hash of their email address
        return self._get_user_queryset().filter(email_hash=email_hash).first()

    def dispatch(self, request, *, token):
        """
        Handle email verification tokens in URLs.

        Makes sure the token is removed from the URL and stored in
        the session.

        Sets the `user` attribute to the user found by the token,
        and the `validlink` attribute to whether the token is valid
        (i.e. it resolves to a user).
        """
        response = self._remove_token_from_url(token)
        if response:
            return response
        self.user = self._get_user_from_token()
        self.validlink = self.user is not None
        return super().dispatch(request, token=token)


class EmailChangeTokenMixin(BaseTokenMixin):
    """Mixin to handle email change tokens in URLs."""

    token_placeholder = "email-change"  # noqa: S105 (not a password)

    def _get_email_change_request_from_token_object(self, token_object):
        """
        Find the email change request associated with the token in the session.

        Returns:
            EmailChangeRequest | None:
                The email change request if the token is valid, otherwise None.
        """
        email_change_request = EmailChangeRequest.objects.filter(
            id=token_object["uuid"]
        ).first()
        if (
            email_change_request is None
            or email_change_request.user != self.request.user
        ):
            return None
        return email_change_request

    def _check_token(self, token):
        token = self.request.session.get(self.token_session_key)
        if token is None:
            return None
        return self.token_generator.check_token(token)

    def dispatch(self, request, *, token):
        """
        Handle email change tokens in URLs.

        Makes sure the token is removed from the URL and stored in
        the session.

        Sets the `email_change_request` attribute to the email change request
        found by the token, and the `validlink` attribute to whether the token
        is valid (i.e. it resolves to an email change request).
        """
        response = self._remove_token_from_url(token)
        if response:
            return response
        token_object = self._check_token(token)
        self.email_change_request = (
            self._get_email_change_request_from_token_object(token_object)
            if token_object
            else None
        )
        self.recipient = token_object["recipient"] if token_object else None
        self.validlink = self.email_change_request is not None
        return super().dispatch(request, token=token)


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(never_cache, name="dispatch")
class EmailVerificationRequiredView(
    auth_views.RedirectURLMixin,
    EmailTokenMixin,
    generic.TemplateView,
):
    """
    Display a notice that the user must verify their email address.

    Can be used to resend the email verification email by sending a POST request.
    """

    template_name = "hidp/accounts/verification/email_verification_required.html"
    token_generator = tokens.email_verification_request_token_generator
    verification_mailer = mailers.EmailVerificationMailer
    token_session_key = "_email_verification_request_token"  # noqa: S105 (not a password)

    def get_context_data(self, **kwargs):
        context = {
            "validlink": self.validlink,
        }
        return super().get_context_data() | context | kwargs

    def send_email(self):
        """Send the email verification email."""
        self.verification_mailer(
            self.user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

    def post(self, *args, **kwargs):
        if self.validlink:
            # Send the email verification email.
            self.send_email()
            # Redirect to the email verification required page, with a new token.
            return HttpResponseRedirect(
                email_verification.get_email_verification_required_url(
                    self.user, next_url=self.get_redirect_url()
                )
            )
        # Invalid token, do nothing and redirect to the same page.
        return HttpResponseRedirect(self.request.get_full_path())


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(never_cache, name="dispatch")
class EmailVerificationView(
    auth_views.RedirectURLMixin,
    EmailTokenMixin,
    generic.UpdateView,
):
    """
    Landing page for email verification links.

    Contains a form that must be submitted to complete the verification process.
    """

    form_class = forms.EmailVerificationForm
    template_name = "hidp/accounts/verification/verify_email.html"
    token_generator = tokens.email_verification_token_generator
    success_url = reverse_lazy("hidp_accounts:email_verification_complete")
    token_session_key = "_email_verification_request_token"  # noqa: S105 (not a password)

    def _get_user_queryset(self):
        return super()._get_user_queryset().email_unverified().filter(is_active=True)

    def get_context_data(self, **kwargs):
        context = {
            "validlink": self.validlink,
        }
        return super().get_context_data() | context | kwargs

    def get_object(self):
        return self.user  # The user from the token

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


@method_decorator(hidp_csp_protection, name="dispatch")
class EmailVerificationCompleteView(auth_views.RedirectURLMixin, generic.TemplateView):
    """Display a message that the email address has been verified."""

    template_name = "hidp/accounts/verification/email_verification_complete.html"

    def get_context_data(self, **kwargs):
        login_url = resolve_url(settings.LOGIN_URL) + (
            f"?{urlencode({'next': redirect_url})}"
            if (redirect_url := self.get_redirect_url())
            else ""
        )
        context = {
            "login_url": login_url,
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(
    ratelimit(key="post:username", rate="10/m", method="POST", block=False), name="post"
)
@method_decorator(rate_limit_strict, name="dispatch")
class LoginView(OIDCContextMixin, auth_views.LoginView):
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
    verification_mailer = mailers.EmailVerificationMailer

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
        context = {
            "register_url": register_url,
            "is_rate_limited": self.request.limited,
        }
        return super().get_context_data() | context | kwargs

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

    def send_email(self, user):
        """Send the email verification email."""
        self.verification_mailer(
            user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

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
        self.send_email(user)

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
        """Log out the user and redirect to the success URL."""
        # This **replaces** the base implementation in order to use the
        # HIdP logout wrapper, for good measure.
        hidp_auth.logout(request)
        redirect_to = self.get_success_url()
        if redirect_to != request.get_full_path():
            # Redirect to target page once the session has been cleared.
            return HttpResponseRedirect(redirect_to)
        return super().get(request, *args, **kwargs)


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
class PasswordResetRequestView(generic.FormView):
    """
    Display and handle the password reset request form.

    Sends the password reset email and redirects to the password reset
    sent view if the form is submitted with valid data.
    """

    form_class = forms.PasswordResetRequestForm
    template_name = "hidp/accounts/recovery/password_reset_request.html"
    success_url = reverse_lazy("hidp_accounts:password_reset_email_sent")
    password_reset_request_mailer = mailers.PasswordResetRequestMailer
    set_password_mailer = mailers.SetPasswordMailer

    def send_email(self, user):
        """Send the appropriate email to the user."""
        if user.has_usable_password():
            mailer_class = self.password_reset_request_mailer
        else:
            mailer_class = self.set_password_mailer
        try:
            mailer_class(
                user=user,
                base_url=self.request.build_absolute_uri("/"),
            ).send()
        except Exception:
            # Do not leak the existence of the user. Log the error and
            # continue as if the email was sent successfully.
            logger.exception("Failed to send password (re)set email.")

    def form_valid(self, form):
        if user := form.get_user():
            self.send_email(user)
        return super().form_valid(form)


@method_decorator(hidp_csp_protection, name="dispatch")
class PasswordResetEmailSentView(generic.TemplateView):
    """Display a message that the password reset email has been sent."""

    template_name = "hidp/accounts/recovery/password_reset_email_sent.html"


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
class PasswordResetView(auth_views.PasswordResetConfirmView):
    """Display the password reset form and handle the password reset action."""

    form_class = forms.PasswordResetForm
    template_name = "hidp/accounts/recovery/password_reset.html"
    success_url = reverse_lazy("hidp_accounts:password_reset_complete")
    password_changed_mailer = mailers.PasswordChangedMailer

    def send_email(self):
        """Send the password changed email."""
        self.password_changed_mailer(
            self.user,
            base_url=self.request.build_absolute_uri("/"),
        ).send()

    def form_valid(self, form):
        response = super().form_valid(form)
        self.send_email()
        return response


@method_decorator(hidp_csp_protection, name="dispatch")
class PasswordResetCompleteView(auth_views.TemplateView):
    """Display a message that the password reset has been completed."""

    template_name = "hidp/accounts/recovery/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        context = {
            "login_url": resolve_url(settings.LOGIN_URL),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
class PasswordChangeView(LoginRequiredMixin, auth_views.PasswordChangeView):
    """Display the password change form and handle the password change action."""

    form_class = forms.PasswordChangeForm
    template_name = "hidp/accounts/management/password_change.html"
    success_url = reverse_lazy("hidp_accounts:change_password_done")
    password_changed_mailer = mailers.PasswordChangedMailer

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not request.user.has_usable_password():
            return HttpResponseRedirect(reverse("hidp_accounts:set_password"))
        return super().dispatch(request, *args, **kwargs)

    def send_email(self):
        """Send the password changed email."""
        self.password_changed_mailer(
            self.request.user,
            base_url=self.request.build_absolute_uri("/"),
        ).send()

    def form_valid(self, form):
        response = super().form_valid(form)
        self.send_email()
        return response


@method_decorator(hidp_csp_protection, name="dispatch")
class PasswordChangeDoneView(auth_views.TemplateView):
    """Display a message that the password change has been completed."""

    template_name = "hidp/accounts/management/password_change_done.html"


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
class SetPasswordView(
    LoginRequiredMixin, OIDCContextMixin, auth_views.PasswordChangeView
):
    """Allow users without a password to set one."""

    form_class = forms.SetPasswordForm
    template_name = "hidp/accounts/management/set_password.html"
    success_url = reverse_lazy("hidp_accounts:set_password_done")
    login_delta = timedelta(minutes=5)
    password_changed_mailer = mailers.PasswordChangedMailer

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if request.user.has_usable_password():
            return HttpResponseRedirect(reverse_lazy("hidp_accounts:change_password"))

        last_login = request.user.last_login
        # If the user has not logged in recently, they must re-authenticate
        # to prove their identity before setting a password.
        self.must_reauthenticate = last_login is None or last_login < (
            timezone.now() - self.login_delta
        )

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = {
            "must_reauthenticate": self.must_reauthenticate,
            "oidc_linked_providers": self._build_provider_url_list(
                [
                    provider
                    for provider in oidc_clients.get_registered_oidc_clients()
                    if provider.provider_key
                    in self.request.user.openid_connections.values_list(
                        "provider_key", flat=True
                    )
                ]
                if self.must_reauthenticate
                else [],
                url_name="hidp_oidc_client:reauthenticate",
            ),
            "auth_next_url": self.request.get_full_path(),
        }
        return super().get_context_data() | context | kwargs

    def post(self, request, *args, **kwargs):
        if self.must_reauthenticate:
            # The user was able to POST the form, but has not logged in recently.
            # Redirect to this view using a GET so they are shown the message
            # that they must re-authenticate.
            return HttpResponseRedirect(reverse("hidp_accounts:set_password"))
        return super().post(request, *args, **kwargs)

    def send_email(self):
        """Send the password changed email."""
        self.password_changed_mailer(
            self.request.user,
            base_url=self.request.build_absolute_uri("/"),
        ).send()

    def form_valid(self, form):
        form.save()
        self.send_email()
        return super().form_valid(form)


@method_decorator(hidp_csp_protection, name="dispatch")
class SetPasswordDoneView(auth_views.TemplateView):
    """Display a message that the password has been set."""

    template_name = "hidp/accounts/management/set_password_done.html"


@method_decorator(hidp_csp_protection, name="dispatch")
class ManageAccountView(LoginRequiredMixin, OIDCContextMixin, generic.TemplateView):
    """Display the manage account page."""

    template_name = "hidp/accounts/management/manage_account.html"

    def get_account_management_links(self):
        links = [
            {
                "url": reverse("hidp_accounts:edit_account"),
                "text": _("Edit account"),
            },
            {
                "url": reverse("hidp_accounts:email_change_request"),
                "text": _("Change email address"),
            },
        ]

        if self.request.user.has_usable_password():
            links.append(
                {
                    "url": reverse("hidp_accounts:change_password"),
                    "text": _("Change password"),
                },
            )
        else:
            links.append(
                {
                    "url": reverse("hidp_accounts:set_password"),
                    "text": _("Set password"),
                },
            )

        if oidc_clients.get_registered_oidc_clients():
            links.append(
                {
                    "url": reverse("hidp_accounts:oidc_linked_services"),
                    "text": _("Linked services"),
                },
            )

        return links

    def get_context_data(self, **kwargs):
        context = {
            "user": self.request.user,
            "logout_url": reverse("hidp_accounts:logout"),
            "account_management_links": self.get_account_management_links(),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
class EditAccountView(LoginRequiredMixin, generic.FormView):
    """Display the edit user form and handle the edit user action."""

    template_name = "hidp/accounts/management/edit_account.html"
    form_class = forms.EditUserForm
    success_url = reverse_lazy("hidp_accounts:edit_account")

    def get_success_url(self):
        return self.success_url + "?success"

    def get_context_data(self, **kwargs):
        context = {
            "show_success_message": "success" in self.request.GET,
        }
        return super().get_context_data() | context | kwargs

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {
            "instance": self.request.user,
        }

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


@method_decorator(hidp_csp_protection, name="dispatch")
class OIDCLinkedServicesView(
    LoginRequiredMixin, OIDCContextMixin, generic.TemplateView
):
    """Display the linked services page."""

    template_name = "hidp/accounts/management/oidc_linked_services.html"

    def get_context_data(self, **kwargs):
        oidc_linked_provider_keys = self.request.user.openid_connections.values_list(
            "provider_key", flat=True
        )
        # Do not allow the user to unlink the only available login method.
        user = self.request.user
        can_unlink = user.has_usable_password() or user.openid_connections.count() > 1
        linked_provider = oidc_clients.get_oidc_client_or_none(
            self.request.GET.get("success")
        )
        removed_provider = oidc_clients.get_oidc_client_or_none(
            self.request.GET.get("removed")
        )
        context = {
            "successfully_linked_provider": linked_provider,
            "removed_provider": removed_provider,
            "oidc_linked_providers": self._build_provider_url_list(
                [
                    provider
                    for provider in oidc_clients.get_registered_oidc_clients()
                    if provider.provider_key in oidc_linked_provider_keys
                ],
                url_name="hidp_oidc_client:unlink_account",
            ),
            "oidc_available_providers": self._build_provider_url_list(
                [
                    provider
                    for provider in oidc_clients.get_registered_oidc_clients()
                    if provider.provider_key not in oidc_linked_provider_keys
                ]
            ),
            "can_unlink": can_unlink,
            "set_password_url": reverse("hidp_accounts:set_password"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
class EmailChangeRequestView(LoginRequiredMixin, generic.CreateView):
    """
    Display and handle the email change request form.

    If the form is submitted with valid data, emails are sent to the user's
    current and proposed email address to confirm the change request.
    The user is then redirected to the success page.
    """

    form_class = forms.EmailChangeRequestForm
    template_name = "hidp/accounts/management/email_change_request.html"
    success_url = reverse_lazy("hidp_accounts:email_change_request_sent")
    email_change_request_mailer = mailers.EmailChangeRequestMailer

    def get_form_kwargs(self):
        return {
            **super().get_form_kwargs(),
            "user": self.request.user,
        }

    def get_context_data(self, **kwargs):
        context = {
            "can_change_email": self.request.user.has_usable_password(),
        }
        return super().get_context_data() | context | kwargs

    def send_email(self, email_change_request):
        """Send the email change confirmation emails."""
        mailer_kwargs = {
            "user": self.request.user,
            "email_change_request": email_change_request,
            "base_url": self.request.build_absolute_uri("/"),
        }
        self.email_change_request_mailer(
            **mailer_kwargs,
            recipient=Recipient.CURRENT_EMAIL,
        ).send()
        self.email_change_request_mailer(
            **mailer_kwargs,
            recipient=Recipient.PROPOSED_EMAIL,
        ).send()

    def form_valid(self, form):
        email_change_request = form.save()
        self.send_email(email_change_request)
        return HttpResponseRedirect(self.success_url)


class EmailChangeRequestSentView(generic.TemplateView):
    """Display a message that the email change request confirmation emails were sent."""

    template_name = "hidp/accounts/management/email_change_request_sent.html"


class EmailChangeConfirmView(
    LoginRequiredMixin,
    EmailChangeTokenMixin,
    generic.UpdateView,
):
    """
    Landing page for email change confirmation links.

    Contains a form that must be submitted to complete the email change process.
    """

    form_class = forms.EmailChangeConfirmForm
    template_name = "hidp/accounts/management/email_change_confirm.html"
    success_url = reverse_lazy("hidp_accounts:email_change_complete")
    token_generator = tokens.email_change_token_generator
    token_session_key = "_email_change_request_token"  # noqa: S105 (not a password)

    def get_context_data(self, **kwargs):
        context = {
            "validlink": self.validlink,
        }
        if self.validlink:
            context |= {
                "recipient": self.recipient,
                "already_confirmed_for_this_email": getattr(
                    self.email_change_request, f"confirmed_by_{self.recipient}"
                ),
                "current_email": self.email_change_request.current_email,
                "proposed_email": self.email_change_request.proposed_email,
            }
        return super().get_context_data() | context | kwargs

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {
            "recipient": self.recipient,
        }

    def get_object(self):
        return self.email_change_request

    def form_valid(self, form):
        form.save()
        return HttpResponseRedirect(self.success_url)


class EmailChangeCompleteView(auth_views.TemplateView):
    """Display a message that the email change has been completed."""

    template_name = "hidp/accounts/management/email_change_complete.html"

    def get_context_data(self, **kwargs):
        email_change_request = EmailChangeRequest.objects.filter(
            user=self.request.user
        ).first()
        if email_change_request is None or email_change_request.is_complete():
            context = {
                "current_email_confirmation_required": False,
                "proposed_email_confirmation_required": False,
                "email_change_request_completed": True,
            }
        else:
            context = {
                "current_email_confirmation_required": (
                    not email_change_request.confirmed_by_current_email
                ),
                "proposed_email_confirmation_required": (
                    not email_change_request.confirmed_by_proposed_email
                ),
                "email_change_request_completed": False,
            }
        return super().get_context_data() | context | kwargs


class EmailChangeCancelView(LoginRequiredMixin, generic.DeleteView):
    """Cancel an email change request."""

    form_class = forms.EmailChangeCancelForm
    template_name = "hidp/accounts/management/email_change_cancel.html"
    success_url = reverse_lazy("hidp_accounts:email_change_cancel_done")
    token_generator = tokens.email_change_token_generator

    def get_context_data(self, **kwargs):
        validlink = self.object is not None
        context = {
            "validlink": validlink,
        }

        if validlink:
            context |= {
                "current_email": self.object.current_email,
                "proposed_email": self.object.proposed_email,
            }

        return super().get_context_data() | context | kwargs

    def get_object(self, queryset=None):
        """
        Get the email change request to cancel.

        But only if there is a request for the current user that has not been confirmed
        by both the current and proposed email addresses, and has not expired.
        """
        return (
            EmailChangeRequest.objects.filter(
                user=self.request.user,
                created_at__gte=(
                    timezone.now()
                    - timedelta(seconds=self.token_generator.token_timeout)
                ),
            )
            .exclude(
                confirmed_by_current_email=True,
                confirmed_by_proposed_email=True,
            )
            .first()
        )

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        if self.object is None:
            # Show invalid or expired link message.
            return self.get(request, *args, **kwargs)
        return super().post(request, *args, **kwargs)


class EmailChangeCancelDoneView(auth_views.TemplateView):
    """Display a message that the email change request has been cancelled."""

    template_name = "hidp/accounts/management/email_change_cancel_done.html"
