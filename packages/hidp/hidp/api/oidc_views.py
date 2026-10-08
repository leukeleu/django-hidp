"""
Logging in with an OIDC provider, for a frontend in place of the HTML views.

The provider redirects to HIdP's callback, which sends the user to the frontend
pages of `HIDP_FRONTEND_URLS` with a `token` for the data the provider sent. These
endpoints take that token.
"""

from http import HTTPStatus

from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import BooleanField, CharField, DictField

from django.http import Http404
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _

from hidp.accounts import auth as hidp_auth
from hidp.config import oidc_clients
from hidp.federated import flows
from hidp.federated.forms import OIDCAccountUnlinkForm
from hidp.federated.oidc import authorization_code_flow
from hidp.oidc_provider.frontend import get_stored_page
from hidp.otp.decorators import otp_exempt
from hidp.rate_limit.decorators import rate_limit_default, rate_limit_strict
from hidp.utils import is_registration_enabled

from .auth_state import auth_state_response, start_email_verification
from .oidc_serializers import (
    OIDCAuthenticateSerializer,
    OIDCConnectionSerializer,
    OIDCLinkSerializer,
    OIDCLinkTokenSerializer,
    OIDCProviderSerializer,
    OIDCRegistrationSerializer,
    OIDCRegistrationTokenSerializer,
)
from .views import (
    AUTH_STATE_RESPONSES,
    FORBIDDEN_RESPONSE,
    BaseView,
    VerificationMailerMixin,
    permission_denied,
)

TOKEN_QUERY = {
    "parameters": [OpenApiParameter("token", str, required=True)],
}


@method_decorator(otp_exempt, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(get=extend_schema(responses=OIDCProviderSerializer(many=True)))
class OIDCProvidersView(BaseView):
    """The OIDC providers that users can log in with."""

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        return Response(
            OIDCProviderSerializer(
                oidc_clients.get_registered_oidc_clients(), many=True
            ).data
        )


@method_decorator(rate_limit_strict, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.OK: inline_serializer(
                name="OIDCAuthenticateResponse",
                fields={"redirect_url": CharField()},
            ),
        },
    )
)
class OIDCAuthenticateView(BaseView):
    """
    Start logging in with a provider: send the user to `redirect_url`.

    The provider returns the user to the frontend, or to `next` after a login.
    With `reauthenticate`, the provider asks for the credentials again, for
    endpoints that need a recent login.
    """

    serializer_class = OIDCAuthenticateSerializer

    def post(self, request, *args, provider_key, **kwargs):
        client = oidc_clients.get_oidc_client_or_404(provider_key)
        if not request.is_secure():
            return Response(
                {"detail": _("Logging in with a provider requires HTTPS.")},
                status=HTTPStatus.BAD_REQUEST,
            )
        data = self.validated_serializer().validated_data
        extra_params = (
            {"prompt": "login", "max_age": 0} if data["reauthenticate"] else {}
        )
        redirect_url = authorization_code_flow.prepare_authentication_request(
            request,
            client=client,
            callback_url=reverse(
                "hidp_oidc_client:callback", kwargs={"provider_key": provider_key}
            ),
            next_url=data.get("next"),
            **extra_params,
        )
        return Response({"redirect_url": redirect_url})


@method_decorator(rate_limit_strict, name="dispatch")
@extend_schema_view(
    get=extend_schema(
        responses=inline_serializer(
            name="OIDCRegistrationDetails",
            fields={
                "provider": OIDCProviderSerializer(),
                "email": CharField(),
                "first_name": CharField(allow_null=True),
                "last_name": CharField(allow_null=True),
                "requires_name": BooleanField(),
            },
        ),
        **TOKEN_QUERY,
    ),
    post=extend_schema(
        responses=AUTH_STATE_RESPONSES | {HTTPStatus.FORBIDDEN: FORBIDDEN_RESPONSE}
    ),
)
class OIDCRegistrationView(VerificationMailerMixin, BaseView):
    """
    Create the account of a user who logs in with a provider for the first time.

    When the provider is trusted to verify email addresses, the user is logged in.
    Otherwise they are sent a verification email, and the response has a pending
    `email_verify` step.
    """

    serializer_class = OIDCRegistrationSerializer

    def initial(self, request, *args, **kwargs):
        if not is_registration_enabled():
            raise Http404("Registration is disabled.")
        super().initial(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        serializer = OIDCRegistrationTokenSerializer(
            data={"token": request.query_params.get("token")},
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        form = self.serializer_class.form_class(
            provider_key=serializer.token_data["provider_key"],
            claims=serializer.token_data["claims"],
            user_info=serializer.token_data["user_info"],
        )
        return Response(
            {
                "provider": OIDCProviderSerializer(serializer.provider).data,
                "email": form.initial["email"],
                "first_name": form.initial["first_name"],
                "last_name": form.initial["last_name"],
                "requires_name": "first_name" in form.fields,
            }
        )

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            raise permission_denied(
                _("Logged-in users cannot register a new account."),
                "already_authenticated",
            )
        serializer = self.validated_serializer()
        try:
            user = flows.register(
                request, serializer.form, token_data=serializer.token_data
            )
        except flows.RegistrationRefusedError:
            user = None
        flows.discard_token_data(request, serializer.validated_data["token"])
        if user is None:
            raise permission_denied(
                _("Login failed. Invalid credentials."), "invalid_credentials"
            )
        if user.email_verified:
            hidp_auth.login(request, user)
        else:
            self.get_verification_mailer(
                next_url=serializer.validated_data.get("next")
            )(user).send()
            start_email_verification(request, user)
        return auth_state_response(request)


@method_decorator(rate_limit_strict, name="dispatch")
@extend_schema_view(
    get=extend_schema(
        responses=inline_serializer(
            name="OIDCLinkDetails",
            fields={
                "provider": OIDCProviderSerializer(),
                "provider_email": CharField(allow_null=True),
                "email": CharField(),
            },
        ),
        **TOKEN_QUERY,
    ),
    post=extend_schema(responses={HTTPStatus.NO_CONTENT: None}),
)
class OIDCLinkView(BaseView):
    """
    Let the logged-in user also log in with a provider.

    The user logged in with the provider while logged in, which sent them to the
    frontend with the token.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = OIDCLinkSerializer

    def get(self, request, *args, **kwargs):
        serializer = OIDCLinkTokenSerializer(
            data={"token": request.query_params.get("token")},
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                "provider": OIDCProviderSerializer(serializer.provider).data,
                "provider_email": serializer.token_data["claims"].get("email"),
                "email": request.user.email,
            }
        )

    def post(self, request, *args, **kwargs):
        serializer = self.validated_serializer()
        serializer.form.save()
        flows.discard_token_data(request, serializer.validated_data["token"])
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(get=extend_schema(responses=OIDCConnectionSerializer(many=True)))
class OIDCConnectionsView(BaseView):
    """
    The providers, and whether the user logs in with them.

    A user keeps at least one way to log in, so `can_unlink` is false for the only
    linked provider of a user without a password.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        user = request.user
        linked = set(user.openid_connections.values_list("provider_key", flat=True))
        connections = [
            {
                "provider_key": client.provider_key,
                "name": client.name,
                "linked": client.provider_key in linked,
                "can_unlink": user.has_usable_password()
                or bool(linked - {client.provider_key}),
            }
            for client in oidc_clients.get_registered_oidc_clients()
        ]
        return Response(OIDCConnectionSerializer(connections, many=True).data)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    delete=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
            HTTPStatus.FORBIDDEN: FORBIDDEN_RESPONSE,
        }
    )
)
class OIDCConnectionView(BaseView):
    """Stop logging in with a provider."""

    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, provider_key, **kwargs):  # noqa: PLR6301
        connections = request.user.openid_connections.filter(provider_key=provider_key)
        if not connections.exists():
            raise Http404
        form = OIDCAccountUnlinkForm(
            user=request.user, provider_key=provider_key, data={"allow_unlink": True}
        )
        if not form.is_valid():
            raise permission_denied(
                _("You cannot unlink your only way to sign in."), "only_login_method"
            )
        connections.delete()
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    get=extend_schema(
        responses=inline_serializer(
            name="OIDCProviderPage",
            fields={
                "page": CharField(help_text="consent, logout or error"),
                "action": CharField(required=False),
                "application": inline_serializer(
                    name="OIDCProviderApplication",
                    fields={"name": CharField(), "client_id": CharField()},
                    allow_null=True,
                    required=False,
                ),
                "scopes": inline_serializer(
                    name="OIDCProviderScope",
                    fields={"scope": CharField(), "description": CharField()},
                    many=True,
                    required=False,
                ),
                "fields": DictField(child=CharField(), required=False),
                "error": CharField(required=False),
                "error_description": CharField(required=False, allow_null=True),
            },
        ),
        **TOKEN_QUERY,
    ),
)
class OIDCProviderPageView(BaseView):
    """
    A page of HIdP's OIDC provider, which the frontend shows in place of HTML.

    The `consent` page asks the user to authorize an application, the `logout` page
    to log out. The frontend posts a form to `action` with `fields`, `allow` set to
    `true` (or left out to refuse), and the `csrfmiddlewaretoken`, as a normal page
    load: the response redirects to the application. The `error` page shows an
    error that could not be sent to the application.
    """

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        page = get_stored_page(request, request.query_params.get("token"))
        if page is None:
            raise ValidationError({"token": [_("The page has expired.")]})
        return Response(page)
