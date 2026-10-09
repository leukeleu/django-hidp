import logging

from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import (
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _
from django.views import generic

from hidp.utils import (
    get_frontend_redirect_url,
    get_frontend_url,
    has_frontend_url,
    is_headless_oidc,
    is_registration_enabled,
)

from ..accounts import auth as hidp_auth
from ..accounts import email_verification, mailers
from ..config import oidc_clients
from ..csp.decorators import hidp_csp_protection
from ..federated.constants import OIDCError
from ..rate_limit.decorators import rate_limit_strict
from . import flows, forms, tokens
from .oidc import authorization_code_flow
from .oidc.exceptions import InvalidOIDCStateError, OAuth2Error

logger = logging.getLogger(__name__)

UserModel = get_user_model()


def get_oidc_error_url(request, error, *, next_url=None, url=None):
    """
    Return the URL of the page that shows an error of logging in with a provider.

    That is the frontend's `login` page when the frontend takes the place of the
    HTML views, otherwise `url` or the HTML login page.
    """
    if is_headless_oidc():
        return get_frontend_redirect_url(
            request, "login", oidc_error=error, next=next_url
        )
    params = {"oidc_error": error} | ({"next": next_url} if next_url else {})
    return f"{url or reverse('hidp_accounts:login')}?{urlencode(params)}"


class FrontendRedirectMixin:
    """Send the request to a frontend page, with its query, in headless mode."""

    frontend_url_key = NotImplemented

    def dispatch(self, request, *args, **kwargs):
        if is_headless_oidc():
            return HttpResponseRedirect(
                get_frontend_redirect_url(
                    request, self.frontend_url_key, **request.GET.dict()
                )
            )
        return super().dispatch(request, *args, **kwargs)


class OIDCMixin:
    callback_pattern = "hidp_oidc_client:callback"

    def dispatch(self, request, *args, **kwargs):
        # Require HTTPS for OIDC requests. This is a security requirement to
        # prevent the authentication request from happening in the clear.
        if not request.is_secure():
            return HttpResponseBadRequest("Insecure request")
        return super().dispatch(request, *args, **kwargs)

    def get_callback_url(self, provider_key):
        return reverse(
            self.callback_pattern,
            kwargs={
                "provider_key": provider_key,
            },
        )


class OIDCContextMixin:
    """Mixin to provide context data for OIDC login providers."""

    oidc_error_messages = {
        OIDCError.ACCOUNT_EXISTS: _(
            "You already have an account with this email address."
            " Please sign in to link your account."
        ),
        OIDCError.REQUEST_EXPIRED: _(
            "The authentication request has expired. Please try again."
        ),
        OIDCError.UNEXPECTED_ERROR: _(
            "An unexpected error occurred during authentication. Please try again."
        ),
        OIDCError.INVALID_TOKEN: _("Expired or invalid token. Please try again."),
        OIDCError.INVALID_CREDENTIALS: _("Login failed. Invalid credentials."),
        OIDCError.REGISTRATION_DISABLED: _("Registration is disabled."),
    }

    @staticmethod
    def _build_provider_url_list(
        providers,
        url_name="hidp_oidc_client:authenticate",
        label=None,
    ):
        return [
            {
                "provider": provider,
                "url": reverse(
                    url_name,
                    kwargs={
                        "provider_key": provider.provider_key,
                    },
                ),
                "label": format_lazy(
                    label or _("Sign in with {provider}"),
                    provider=provider.name,
                ),
            }
            for provider in providers
        ]

    def get_context_data(self, **kwargs):
        oidc_error = self.request.GET.get("oidc_error", None)
        context = {
            "oidc_error": oidc_error,
            "oidc_login_providers": self._build_provider_url_list(
                oidc_clients.get_registered_oidc_clients()
            ),
            "oidc_error_message": self.oidc_error_messages.get(oidc_error, oidc_error),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
class OIDCAuthenticationRequestView(
    auth_views.RedirectURLMixin, OIDCMixin, generic.View
):
    """Initiates an OpenID Connect Authorization Code Flow authentication request."""

    # Optionally set extra parameters to include in the authentication request.
    # I.e. to modify the prompt parameter.
    extra_authentication_request_params = None

    http_method_names = [
        "post",
        "options",
    ]

    def post(self, request, *, provider_key):
        """
        Handle the OIDC authentication request.

        Prepare the authentication request parameters, update the session state
        with the required information, and redirect the user to the OpenID Connect
        provider's authorization endpoint.
        """
        return HttpResponseRedirect(
            authorization_code_flow.prepare_authentication_request(
                request,
                client=oidc_clients.get_oidc_client_or_404(provider_key),
                callback_url=self.get_callback_url(provider_key),
                next_url=self.get_redirect_url(),
                **(self.extra_authentication_request_params or {}),
            )
        )


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCAuthenticationCallbackView(OIDCMixin, generic.View):
    """
    Handle the callback from an OIDC authentication request.

    This view is used for both successful and failed authentication attempts.
    """

    http_method_names = [
        "get",
        "options",
    ]

    def get_next_url(  # noqa: PLR6301 (no-self-use)
        self,
        *,
        request,
        provider_key,
        claims,
        user_info,
        redirect_url=None,
    ):
        """Decide which flow the user should be redirected to next."""
        step, token = flows.resolve_callback(
            request, provider_key=provider_key, claims=claims, user_info=user_info
        )
        if step == flows.CallbackStep.ACCOUNT_EXISTS:
            # Display a message instructing the user to log in to link the accounts.
            # Respect the `next` parameter if it is present in the request.
            if redirect_url and not url_has_allowed_host_and_scheme(
                url=redirect_url,
                allowed_hosts=request.get_host(),
                require_https=request.is_secure(),
            ):
                redirect_url = None
            return get_oidc_error_url(
                request, OIDCError.ACCOUNT_EXISTS, next_url=redirect_url
            )

        if is_headless_oidc() and step != flows.CallbackStep.LOGIN:
            # The frontend registers or links with the API, using the token.
            if step == flows.CallbackStep.REGISTER and not is_registration_enabled():
                flows.discard_token_data(request, token)
                return get_oidc_error_url(request, OIDCError.REGISTRATION_DISABLED)
            return get_frontend_redirect_url(
                request,
                "oidc_registration"
                if step == flows.CallbackStep.REGISTER
                else "oidc_link",
                token=token,
                next=redirect_url,
            )

        view_name = {
            flows.CallbackStep.LOGIN: "hidp_oidc_client:login",
            flows.CallbackStep.REGISTER: "hidp_oidc_client:register",
            flows.CallbackStep.LINK: "hidp_oidc_management:link_account",
        }[step]
        # Prepare the URL parameters for the next view. Drop any None values.
        params = {
            key: value
            for key, value in (
                ("token", token),
                ("next", redirect_url),
            )
            if value is not None
        }
        return reverse(view_name) + f"?{urlencode(params)}"

    def get(self, request, provider_key):
        try:
            _tokens, claims, user_info, next_url = (
                authorization_code_flow.handle_authentication_callback(
                    request,
                    client=oidc_clients.get_oidc_client_or_404(provider_key),
                    callback_url=self.get_callback_url(provider_key),
                )
            )
        except InvalidOIDCStateError:
            # The state parameter in the callback is not present in the session.
            # The user might have tampered with the state parameter, the session
            # might have expired or the authentication request might have expired.
            # Redirect the user to the login page to try again.
            logger.exception("Invalid OIDC state parameter")
            return HttpResponseRedirect(
                get_oidc_error_url(request, OIDCError.REQUEST_EXPIRED)
            )
        except OAuth2Error:
            # One of many things went wrong during the authentication process.
            # Redirect the user to the login page to try again.
            logger.exception("Error during OIDC authentication")
            return HttpResponseRedirect(
                get_oidc_error_url(request, OIDCError.UNEXPECTED_ERROR)
            )

        return HttpResponseRedirect(
            self.get_next_url(
                request=request,
                provider_key=provider_key,
                claims=claims,
                user_info=user_info,
                redirect_url=next_url,
            )
        )


class TokenDataMixin:
    """Mixin to set, retrieve and validate data to/from the session using a token."""

    token_generator = NotImplemented
    invalid_token_redirect_url = reverse_lazy("hidp_accounts:login")

    @classmethod
    def add_data_to_session(cls, request, *, provider_key, claims, user_info):
        return flows.store_token_data(
            request,
            cls.token_generator,
            provider_key=provider_key,
            claims=claims,
            user_info=user_info,
        )

    def dispatch(self, request, *args, **kwargs):
        self.token = request.GET.get("token")
        self.token_data = flows.get_token_data(
            request, self.token, token_generator=self.token_generator
        )
        self.provider = (
            oidc_clients.get_oidc_client(self.token_data["provider_key"])
            if self.token_data
            else None
        )

        if self.token_data is None:
            return HttpResponseRedirect(
                get_oidc_error_url(
                    request,
                    OIDCError.INVALID_TOKEN,
                    url=self.invalid_token_redirect_url,
                )
            )
        return super().dispatch(request, *args, **kwargs)


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
class OIDCRegistrationView(
    FrontendRedirectMixin,
    auth_views.RedirectURLMixin,
    TokenDataMixin,
    generic.FormView,
):
    """Register a new user using the OIDC provider's claims and user info."""

    frontend_url_key = "oidc_registration"

    token_generator = tokens.OIDCRegistrationTokenGenerator()
    form_class = forms.OIDCRegistrationForm
    template_name = "hidp/federated/registration.html"
    next_page = "/"
    verification_mailer = mailers.EmailVerificationMailer
    invalid_token_redirect_url = reverse_lazy("hidp_accounts:register")

    def dispatch(self, request, *args, **kwargs):
        if not is_registration_enabled():
            # Registration is disabled. Redirect to the login page.
            return HttpResponseRedirect(
                get_oidc_error_url(request, OIDCError.REGISTRATION_DISABLED)
            )
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {
            "provider_key": self.token_data["provider_key"],
            "claims": self.token_data["claims"],
            "user_info": self.token_data["user_info"],
        }

    def send_email(self, user):
        """Send the email verification email to the user."""
        self.verification_mailer(
            user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

    def form_valid(self, form):
        try:
            user = flows.register(self.request, form, token_data=self.token_data)
        except flows.RegistrationRefusedError:
            user = None
        # Remove the token from the session after the form has been saved.
        flows.discard_token_data(self.request, self.token)

        if user is None:
            return HttpResponseRedirect(
                get_oidc_error_url(self.request, OIDCError.INVALID_CREDENTIALS)
            )
        if user.email_verified:
            # The provider verified the email address.
            hidp_auth.login(self.request, user)
            return HttpResponseRedirect(self.get_success_url())

        # Send the email verification email.
        self.send_email(user)

        # Redirect to the email verification required page.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
class OIDCLoginView(auth_views.RedirectURLMixin, TokenDataMixin, generic.FormView):
    """Log in a user using the OIDC provider's claims."""

    token_generator = tokens.OIDCLoginTokenGenerator()
    next_page = "/"
    verification_mailer = mailers.EmailVerificationMailer

    def send_email(self, user):
        """Send the email verification email to the user."""
        self.verification_mailer(
            user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

    def start_headless_email_verification(self, user):
        """
        Send the verification email with a link to the frontend, like the API login.

        The frontend shows the pending `email_verify` step of the session.
        """
        from hidp.api.auth_state import start_email_verification  # noqa: PLC0415

        # Do not stay logged in as another user while waiting for `user`.
        if self.request.user.is_authenticated:
            hidp_auth.logout(self.request)
        base_url = self.request.build_absolute_uri("/")
        next_url = self.get_redirect_url() or None
        self.verification_mailer(
            user,
            base_url=base_url,
            verification_url=get_frontend_url("email_verification", base_url=base_url),
            post_verification_redirect=next_url,
        ).send()
        start_email_verification(self.request, user)
        return HttpResponseRedirect(
            get_frontend_redirect_url(
                self.request,
                "email_verification_required"
                if has_frontend_url("email_verification_required")
                else "login",
                next=next_url,
            )
        )

    def get(self, request):
        """
        User has provided valid credentials and is allowed to log in.

        Persist the user and backend in the session and redirect to the
        success URL.

        If the user's email address has not been verified, redirect them
        to the email verification required flow.
        """
        user = flows.authenticate(request, self.token_data)
        # The token is for one login.
        flows.discard_token_data(request, self.token)
        if user is None:
            # The user could not be authenticated using the OIDC claims.
            # The account is probably disabled. Just redirect to the login page.
            return HttpResponseRedirect(
                get_oidc_error_url(request, OIDCError.INVALID_CREDENTIALS)
            )

        if user.email_verified:
            # Only log in the user if their email address has been verified.
            hidp_auth.login(self.request, user)
            return HttpResponseRedirect(self.get_success_url())

        if is_headless_oidc():
            return self.start_headless_email_verification(user)

        # If the user's email address is not yet verified:
        # Send the email verification email.
        self.send_email(user)

        # Then redirect them to the email verification required page.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OIDCAccountLinkView(FrontendRedirectMixin, TokenDataMixin, generic.FormView):
    """Link an existing user account to an OIDC account."""

    frontend_url_key = "oidc_link"

    form_class = forms.OIDCAccountLinkForm
    template_name = "hidp/federated/account_link.html"
    token_generator = tokens.OIDCAccountLinkTokenGenerator()
    invalid_token_redirect_url = reverse_lazy("hidp_oidc_management:linked_services")

    def get_success_url(self):
        return reverse(
            "hidp_oidc_management:link_account_done",
            kwargs={"provider_key": self.provider.provider_key},
        )

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {
            "user": self.request.user,
            "provider_key": self.token_data["provider_key"],
            "claims": self.token_data["claims"],
        }

    def get_context_data(self, **kwargs):
        context = {
            "provider": self.provider,
            "user_email": self.request.user.email,
            "provider_email": self.token_data["claims"]["email"],
            "cancel_url": reverse("hidp_oidc_management:linked_services"),
        }
        return super().get_context_data() | context | kwargs

    def form_valid(self, form):
        form.save()
        # Remove the token from the session after the form has been saved.
        del self.request.session[self.token]

        return super().form_valid(form)


@method_decorator(hidp_csp_protection, name="dispatch")
class OIDCAccountLinkDoneView(LoginRequiredMixin, generic.TemplateView):
    """Show a success message after linking an OIDC account."""

    template_name = "hidp/federated/account_link_done.html"

    def get_context_data(self, **kwargs):
        context = {
            "provider": oidc_clients.get_oidc_client_or_404(
                self.kwargs["provider_key"]
            ),
            "back_url": reverse("hidp_oidc_management:linked_services"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
class OIDCAccountUnlinkView(LoginRequiredMixin, generic.DeleteView):
    """Unlink an OIDC account from an existing user account."""

    form_class = forms.OIDCAccountUnlinkForm
    template_name = "hidp/federated/account_unlink.html"
    slug_field = "provider_key"
    slug_url_kwarg = "provider_key"

    def dispatch(self, request, *args, provider_key, **kwargs):
        self.provider = oidc_clients.get_oidc_client_or_404(provider_key)
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        return reverse(
            "hidp_oidc_management:unlink_account_done",
            kwargs={"provider_key": self.provider.provider_key},
        )

    def get_queryset(self):
        return self.request.user.openid_connections

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {
            "user": self.request.user,
            "provider_key": self.provider.provider_key,
        }

    def get_context_data(self, **kwargs):
        context = {
            "provider": self.provider,
            "cancel_url": reverse("hidp_oidc_management:linked_services"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
class OIDCAccountUnlinkDoneView(LoginRequiredMixin, generic.TemplateView):
    """Show a success message after unlinking an OIDC account."""

    template_name = "hidp/federated/account_unlink_done.html"

    def get_context_data(self, **kwargs):
        context = {
            "provider": oidc_clients.get_oidc_client_or_404(
                self.kwargs["provider_key"]
            ),
            "back_url": reverse("hidp_oidc_management:linked_services"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
class OIDCLinkedServicesView(
    LoginRequiredMixin, OIDCContextMixin, generic.TemplateView
):
    """Display the linked services page."""

    template_name = "hidp/federated/linked_services.html"

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
                (
                    provider
                    for provider in oidc_clients.get_registered_oidc_clients()
                    if provider.provider_key in oidc_linked_provider_keys
                ),
                url_name="hidp_oidc_management:unlink_account",
                label=_("Unlink from {provider}"),
            ),
            "oidc_available_providers": self._build_provider_url_list(
                (
                    provider
                    for provider in oidc_clients.get_registered_oidc_clients()
                    if provider.provider_key not in oidc_linked_provider_keys
                ),
                label=_("Link with {provider}"),
            ),
            "can_unlink": can_unlink,
            "set_password_url": reverse("hidp_account_management:set_password"),
            "back_url": reverse("hidp_account_management:manage_account"),
        }
        return super().get_context_data() | context | kwargs
