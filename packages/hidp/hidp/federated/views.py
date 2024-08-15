from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.http import (
    Http404,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    JsonResponse,
)
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView, View

from ..config import oidc_clients
from ..rate_limit.decorators import rate_limit_strict
from . import forms, tokens
from .oidc import authorization_code_flow
from .oidc.exceptions import InvalidOIDCStateError, OAuth2Error


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

    def get_redirect_uri(self, provider_key):
        return reverse(
            self.callback_pattern,
            kwargs={
                "provider_key": provider_key,
            },
        )


@method_decorator(rate_limit_strict, name="dispatch")
class OIDCAuthenticationRequestView(OIDCMixin, View):
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
                redirect_uri=self.get_redirect_uri(provider_key),
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

    def get(self, request, provider_key):
        try:
            tokens, claims, user_info = (
                authorization_code_flow.handle_authentication_callback(
                    request,
                    client=self.get_oidc_client(provider_key),
                    redirect_uri=self.get_redirect_uri(provider_key),
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

        return JsonResponse(
            {
                "tokens": tokens,
                "claims": claims,
                "user_info": user_info,
            }
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
    template_name = "federated/registration.html"
    next_page = "/"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            provider_key=self.token_data["provider_key"],
            claims=self.token_data["claims"],
            user_info=self.token_data["user_info"],
        )
        return kwargs

    def form_valid(self, form):
        form.save()
        # Remove the token from the session after the form has been saved.
        del self.request.session[self.token]
        return super().form_valid(form)
