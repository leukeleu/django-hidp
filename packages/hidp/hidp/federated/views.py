from django_ratelimit.decorators import ratelimit

from django.http import (
    Http404,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    JsonResponse,
)
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import View

from ..config import oidc_clients
from .oidc import authorization_code_flow


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


@method_decorator(ratelimit(key="ip", rate="10/s", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="30/m", method="POST"), name="post")
@method_decorator(ratelimit(key="ip", rate="100/15m", method="POST"), name="post")
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


@method_decorator(ratelimit(key="ip", rate="10/s", method="GET"), name="get")
@method_decorator(ratelimit(key="ip", rate="30/m", method="GET"), name="get")
@method_decorator(ratelimit(key="ip", rate="100/15m", method="GET"), name="get")
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
        tokens, claims = authorization_code_flow.handle_authentication_callback(
            request,
            client=self.get_oidc_client(provider_key),
            redirect_uri=self.get_redirect_uri(provider_key),
        )
        return JsonResponse(
            {
                "tokens": tokens,
                "claims": claims,
            }
        )
