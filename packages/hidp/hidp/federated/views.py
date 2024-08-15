from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.http import (
    Http404,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView, View

from ..accounts import auth as hidp_auth
from ..accounts import email_verification, mailer
from ..config import oidc_clients
from ..rate_limit.decorators import rate_limit_strict
from . import forms, tokens
from .models import OpenIdConnection
from .oidc import authorization_code_flow
from .oidc.exceptions import InvalidOIDCStateError, OAuth2Error

UserModel = get_user_model()


class OIDCMixin:
    callback_pattern = "hidp_oidc_client:callback"

    def dispatch(self, request, *args, **kwargs):
        # Require HTTPS for OIDC requests. This is a security requirement to
        # prevent the authentication request from happening in the clear.
        if not request.is_secure():
            return HttpResponseBadRequest("Insecure request")
        return super().dispatch(request, *args, **kwargs)

    def get_oidc_client(self, provider_key):  # noqa: PLR6301 (no-self-use)
        try:
            return oidc_clients.get_oidc_client(provider_key)
        except KeyError:
            raise Http404(f"OIDC Client not found: {provider_key!r}") from None

    def get_callback_url(self, provider_key):
        return reverse(
            self.callback_pattern,
            kwargs={
                "provider_key": provider_key,
            },
        )


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCAuthenticationRequestView(auth_views.RedirectURLMixin, OIDCMixin, View):
    """
    Initiates an OpenID Connect Authorization Code Flow authentication request.
    """

    http_method_names = [
        "post",
        "options",
    ]

    def post(self, request, *, provider_key):
        """
        Prepare the authentication request parameters, update the session state
        with the required information, and redirect the user to the OpenID Connect
        provider's authorization endpoint.
        """
        return HttpResponseRedirect(
            authorization_code_flow.prepare_authentication_request(
                request,
                client=self.get_oidc_client(provider_key),
                callback_url=self.get_callback_url(provider_key),
                next_url=self.get_redirect_url(),
            )
        )


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCAuthenticationCallbackView(OIDCMixin, View):
    """
    Handles the callback response from an OpenID Connect Authorization Code Flow
    authentication request. This handles both successful and failed responses.
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
        """
        Decide which flow the user should be redirected to next.
        """
        view_name = None
        token = None
        connection = OpenIdConnection.objects.get_by_provider_and_claims(
            provider_key=provider_key,
            issuer_claim=claims["iss"],
            subject_claim=claims["sub"],
        )
        if connection:
            # A connection exists for the given claims. This must be a login attempt.
            token = OIDCLoginView.add_data_to_session(
                request,
                provider_key=provider_key,
                claims=claims,
                user_info=user_info,
            )
            view_name = "hidp_oidc_client:login"
        elif request.user.is_anonymous:
            # No user is logged in. Check if a user exists for the given email.
            user = UserModel.objects.filter(email__iexact=claims["email"]).first()
            if not user:
                # `sub` and `email` claim do not match an existing user:
                # Redirect the user to the registration page.
                token = OIDCRegistrationView.add_data_to_session(
                    request,
                    provider_key=provider_key,
                    claims=claims,
                    user_info=user_info,
                )
                view_name = "hidp_oidc_client:register"

        if not view_name:
            raise NotImplementedError("No view name was determined for the next step.")

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
                    client=self.get_oidc_client(provider_key),
                    callback_url=self.get_callback_url(provider_key),
                )
            )
        except InvalidOIDCStateError:
            # The state parameter in the callback is not present in the session.
            # The user might have tampered with the state parameter, the session
            # might have expired or the authentication request might have expired.
            # Redirect the user to the login page to try again.
            messages.error(
                request,
                _("The authentication request has expired. Please try again."),
            )
            return HttpResponseRedirect(reverse("hidp_accounts:login"))
        except OAuth2Error:
            # One of many things went wrong during the authentication process.
            # Redirect the user to the login page to try again.
            messages.error(
                request,
                _("Unexpected error during authentication. Please try again."),
            )
            return HttpResponseRedirect(reverse("hidp_accounts:login"))

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
    """
    Mixin to set, retrieve and validate data to/from the session using a token.
    """

    token_generator = NotImplemented
    invalid_token_message = _("Expired or invalid token. Please try again.")
    invalid_token_redirect_url = reverse_lazy("hidp_accounts:login")

    @classmethod
    def add_data_to_session(cls, request, *, provider_key, claims, user_info):
        token = cls.token_generator.make_token()
        request.session[token] = {
            "provider_key": provider_key,
            "claims": claims,
            "user_info": user_info,
        }
        return token

    def dispatch(self, request, *args, **kwargs):
        self.token = request.GET.get("token")
        valid_token = self.token and self.token_generator.check_token(self.token)
        self.token_data = valid_token and request.session.get(self.token)
        if not valid_token or self.token_data is None:
            messages.error(request, self.invalid_token_message)
            return HttpResponseRedirect(self.invalid_token_redirect_url)
        return super().dispatch(request, *args, **kwargs)


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCRegistrationView(auth_views.RedirectURLMixin, TokenDataMixin, FormView):
    """
    Handles the registration process for a new user using an OpenID Connect
    authentication response.
    """

    token_generator = tokens.OIDCRegistrationTokenGenerator()
    form_class = forms.OIDCRegistrationForm
    template_name = "hidp/federated/registration.html"
    next_page = "/"
    verification_mailer = mailer.EmailVerificationMailer

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            provider_key=self.token_data["provider_key"],
            claims=self.token_data["claims"],
            user_info=self.token_data["user_info"],
        )
        return kwargs

    def form_valid(self, form):
        user = form.save()
        # Remove the token from the session after the form has been saved.
        del self.request.session[self.token]

        # Send the email verification email.
        self.verification_mailer(
            user,
            base_url=self.request.build_absolute_uri("/"),
            post_verification_redirect=self.get_redirect_url(),
        ).send()

        # Redirect to the email verification required page.
        return HttpResponseRedirect(
            email_verification.get_email_verification_required_url(
                user, next_url=self.get_redirect_url()
            )
        )


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCLoginView(auth_views.RedirectURLMixin, TokenDataMixin, FormView):
    """
    Handles the login process for a user using an OpenID Connect authentication
    response.
    """

    token_generator = tokens.OIDCLoginTokenGenerator()
    next_page = "/"
    verification_mailer = mailer.EmailVerificationMailer

    def get(self, request):
        """
        User has provided valid credentials and is allowed to log in.

        Persist the user and backend in the session and redirect to the
        success URL.

        If the user's email address has not been verified, redirect them
        to the email verification required flow.
        """
        user = hidp_auth.authenticate(
            request,
            provider_key=self.token_data["provider_key"],
            issuer_claim=self.token_data["claims"]["iss"],
            subject_claim=self.token_data["claims"]["sub"],
        )
        if user is None:
            # The user could not be authenticated using the OIDC claims.
            # The account is probably disabled. Just redirect to the login page.
            messages.error(request, _("Login failed. Invalid credentials."))
            return HttpResponseRedirect(reverse("hidp_accounts:login"))

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
