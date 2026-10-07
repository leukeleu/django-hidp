from functools import partial
from http import HTTPStatus

from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import exceptions
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import BooleanField, CharField
from rest_framework.settings import api_settings

from django.db import connections, transaction
from django.http import Http404
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts import auth as hidp_auth
from hidp.accounts import flows, mailers, tokens
from hidp.accounts.email_change import get_pending_email_change_request
from hidp.utils import is_registration_enabled

from ..rate_limit.decorators import rate_limit, rate_limit_default, rate_limit_strict
from ..rate_limit.keys import ip_username_rate_limit_key
from .auth_state import (
    auth_state_response,
    get_email_verification_user,
    start_email_verification,
)
from .serializers import (
    AuthStateSerializer,
    EmailChangeConfirmSerializer,
    EmailChangeRequestSerializer,
    EmailChangeSerializer,
    EmailVerificationConfirmSerializer,
    EmailVerificationTokenSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetRequestSerializer,
    SetPasswordSerializer,
    SignupSerializer,
    get_user_serializer_class,
)
from .utils import (
    AccessTokenScopePermission,
    CSRFProtectedAPIView,
    get_authentication_classes,
    get_frontend_url,
)

AUTH_STATE_RESPONSES = {
    HTTPStatus.OK: AuthStateSerializer,
    HTTPStatus.UNAUTHORIZED: AuthStateSerializer,
}

FORBIDDEN_RESPONSE = OpenApiResponse(
    inline_serializer(
        name="ForbiddenResponse",
        fields={
            "detail": CharField(),
            "code": CharField(),
        },
    ),
    description="`code` says why the user may not do this.",
)

NO_CONTENT_OR_FORBIDDEN = {
    HTTPStatus.NO_CONTENT: None,
    HTTPStatus.FORBIDDEN: FORBIDDEN_RESPONSE,
}


def permission_denied(detail, code):
    """Return a 403 error with a `code` for the client next to the `detail`."""
    return exceptions.PermissionDenied({"detail": detail, "code": code})


def _password_not_set():
    return permission_denied(
        _("Your account does not currently have a password set."),
        "password_not_set",
    )


@method_decorator(never_cache, name="dispatch")
class BaseView(CSRFProtectedAPIView, GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = []

    @property
    def base_url(self):
        return self.request.build_absolute_uri("/")

    def frontend_url(self, key):
        return get_frontend_url(key, base_url=self.base_url)

    def validated_serializer(self):
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        return serializer

    def handle_exception(self, exc):
        if not isinstance(exc, exceptions.ValidationError):
            return super().handle_exception(exc)
        # DRF's exception handler rolls back ATOMIC_REQUESTS transactions. Keep the
        # writes of a rejected form, such as an OTP throttle's failure count.
        rollback = {
            connection.alias: transaction.get_rollback(using=connection.alias)
            for connection in connections.all(initialized_only=True)
            if connection.settings_dict["ATOMIC_REQUESTS"]
            and connection.in_atomic_block
        }
        response = super().handle_exception(exc)
        for alias, needs_rollback in rollback.items():
            transaction.set_rollback(needs_rollback, using=alias)
        return response


class VerificationMailerMixin:
    verification_mailer = mailers.EmailVerificationMailer

    def get_verification_mailer(self):
        return partial(
            self.verification_mailer,
            base_url=self.base_url,
            verification_url=self.frontend_url("email_verification"),
        )


class PasswordChangedMailerMixin:
    password_changed_mailer = mailers.PasswordChangedMailer

    def send_password_changed_mail(self, user):
        self.password_changed_mailer(
            user,
            base_url=self.base_url,
            password_reset_url=self.frontend_url("password_reset_request"),
        ).send()


@method_decorator(ensure_csrf_cookie, name="dispatch")
@extend_schema_view(get=extend_schema(responses=AUTH_STATE_RESPONSES))
class SessionView(BaseView):
    """
    Describe the authentication state of the current session.

    Also sets the CSRF cookie, which clients need for every unsafe request.
    """

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        return auth_state_response(request)


@method_decorator(sensitive_post_parameters("username", "password"), name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
@method_decorator(
    rate_limit(key=ip_username_rate_limit_key, rate="10/m", method="POST"),
    name="dispatch",
)
@extend_schema_view(post=extend_schema(responses=AUTH_STATE_RESPONSES))
class LoginView(VerificationMailerMixin, BaseView):
    """
    Log in with a username and password.

    A user whose email address is not verified is sent a verification email instead,
    and the response has a pending `email_verify` step.
    """

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        user = self.validated_serializer().form.get_user()
        if not flows.login(request, user):
            self.get_verification_mailer()(user).send()
            start_email_verification(request, user)
        return auth_state_response(request)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        request=None,
        responses={HTTPStatus.UNAUTHORIZED: AuthStateSerializer},
    )
)
class LogoutView(BaseView):
    """Log out, whether or not a user is logged in."""

    def post(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        hidp_auth.logout(request)
        return auth_state_response(request)


@method_decorator(sensitive_post_parameters("password"), name="dispatch")
@method_decorator(rate_limit(key="ip", rate="2/s", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="ip", rate="5/m", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="ip", rate="30/15m", method="POST"), name="dispatch")
@extend_schema_view(
    post=extend_schema(responses={HTTPStatus.UNAUTHORIZED: AuthStateSerializer})
)
class SignupView(VerificationMailerMixin, BaseView):
    """
    Create an account, and send the email to verify it.

    Responds with a pending `email_verify` step whether or not the account existed.
    """

    serializer_class = SignupSerializer
    account_exists_mailer = mailers.AccountExistsMailer

    def initial(self, request, *args, **kwargs):
        if not is_registration_enabled():
            raise Http404("Registration is disabled.")
        super().initial(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            raise permission_denied(
                _("Logged-in users cannot register a new account."),
                "already_authenticated",
            )
        user = flows.register(self.validated_serializer().form)
        flows.send_registration_email(
            user,
            verification_mailer=self.get_verification_mailer(),
            account_exists_mailer=partial(
                self.account_exists_mailer,
                base_url=self.base_url,
                password_reset_url=self.frontend_url("password_reset_request"),
            ),
        )
        start_email_verification(request, user)
        return auth_state_response(request)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(request=None, responses={HTTPStatus.NO_CONTENT: None}),
)
class EmailVerificationResendView(VerificationMailerMixin, BaseView):
    """
    Resend the verification email to the user this session is waiting for.

    Always responds with 204, so the response does not reveal whether an email
    was sent.
    """

    def post(self, request, *args, **kwargs):
        user = get_email_verification_user(request)
        if user is not None:
            self.get_verification_mailer()(user).send()
            start_email_verification(request, user)
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.OK: inline_serializer(
                name="EmailVerificationVerifyResponse",
                fields={"requires_name": BooleanField()},
            ),
        },
    ),
)
class EmailVerificationVerifyView(BaseView):
    """
    Check an email verification token before confirming it.

    Tells the client whether the confirmation must include a first and last name.
    """

    serializer_class = EmailVerificationTokenSerializer

    def post(self, request, *args, **kwargs):
        user = self.validated_serializer().validated_data["user"]
        return Response({"requires_name": not (user.first_name and user.last_name)})


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses={HTTPStatus.NO_CONTENT: None}))
class EmailVerificationConfirmView(BaseView):
    """Mark the email address as verified. The user still has to log in."""

    serializer_class = EmailVerificationConfirmSerializer

    def post(self, request, *args, **kwargs):
        self.validated_serializer().form.save()
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(never_cache, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
class UserView(RetrieveUpdateAPIView):
    """
    The logged-in user.

    With HIdP's OIDC provider installed, an OAuth2 access token with the `profile`
    and `email` scopes can read the user too, but not change it.
    """

    http_method_names = ["get", "patch", "head", "options"]
    permission_classes = [IsAuthenticated, AccessTokenScopePermission]

    def get_authenticators(self):  # noqa: PLR6301 (no-self-use)
        return [
            authentication_class()
            for authentication_class in get_authentication_classes()
        ]

    def get_serializer_class(self):  # noqa: PLR6301 (no-self-use)
        return get_user_serializer_class()

    def get_object(self):
        return self.request.user


@method_decorator(rate_limit_strict, name="dispatch")
@extend_schema_view(post=extend_schema(responses={HTTPStatus.NO_CONTENT: None}))
class PasswordResetRequestView(BaseView):
    """
    Email a password reset link, or a set password link to a user without a password.

    Always responds with 204, so the response does not reveal whether an account
    exists.
    """

    serializer_class = PasswordResetRequestSerializer
    password_reset_request_mailer = mailers.PasswordResetRequestMailer
    set_password_mailer = mailers.SetPasswordMailer

    def post(self, request, *args, **kwargs):
        if user := self.validated_serializer().form.get_user():
            flows.send_password_reset_email(
                user,
                password_reset_mailer=partial(
                    self.password_reset_request_mailer,
                    base_url=self.base_url,
                    password_reset_url=self.frontend_url("password_reset"),
                ),
                set_password_mailer=partial(
                    self.set_password_mailer,
                    base_url=self.base_url,
                    set_password_url=self.frontend_url("set_password"),
                ),
            )
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(
    sensitive_post_parameters("token", "uidb64", "new_password"), name="dispatch"
)
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses={HTTPStatus.NO_CONTENT: None}))
class PasswordResetConfirmationView(PasswordChangedMailerMixin, BaseView):
    """
    Set a new password for the user identified by the password reset token.

    Changing the password invalidates the user's existing sessions. The user still
    has to log in.
    """

    serializer_class = PasswordResetConfirmationSerializer

    def post(self, request, *args, **kwargs):
        user = self.validated_serializer().form.save()
        self.send_password_changed_mail(user)
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(
    sensitive_post_parameters("old_password", "new_password"), name="dispatch"
)
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses=NO_CONTENT_OR_FORBIDDEN))
class PasswordChangeView(PasswordChangedMailerMixin, BaseView):
    """Change the password of the logged-in user, who must enter the current one."""

    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def post(self, request, *args, **kwargs):
        if not request.user.has_usable_password():
            raise _password_not_set()
        user = flows.change_password(request, self.validated_serializer().form)
        self.send_password_changed_mail(user)
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(sensitive_post_parameters("new_password"), name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses=NO_CONTENT_OR_FORBIDDEN))
class SetPasswordView(PasswordChangedMailerMixin, BaseView):
    """
    Set a password for a logged-in user who does not have one.

    Only allowed shortly after logging in, to prove the user's identity.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = SetPasswordSerializer
    login_delta = flows.REAUTHENTICATION_DELTA

    def post(self, request, *args, **kwargs):
        if request.user.has_usable_password():
            raise permission_denied(
                _("Your account already has a password."), "password_already_set"
            )
        if flows.requires_reauthentication(request.user, delta=self.login_delta):
            raise permission_denied(
                _(
                    "For your security, you need to re-authenticate via a linked"
                    " service before you can set a password."
                ),
                "reauthentication_required",
            )
        user = flows.change_password(request, self.validated_serializer().form)
        self.send_password_changed_mail(user)
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(sensitive_post_parameters("password"), name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    get=extend_schema(responses=EmailChangeSerializer),
    post=extend_schema(
        request=EmailChangeRequestSerializer,
        responses={
            HTTPStatus.CREATED: EmailChangeSerializer,
            HTTPStatus.FORBIDDEN: FORBIDDEN_RESPONSE,
        },
    ),
    delete=extend_schema(responses={HTTPStatus.NO_CONTENT: None}),
)
class EmailChangeView(BaseView):
    """
    The pending email change request of the logged-in user.

    Starting a new request replaces the pending one.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = EmailChangeRequestSerializer
    email_change_request_mailer = mailers.EmailChangeRequestMailer
    proposed_email_exists_mailer = mailers.ProposedEmailExistsMailer
    token_generator = tokens.email_change_token_generator

    def get_object(self):
        if email_change_request := get_pending_email_change_request(
            self.request.user, token_generator=self.token_generator
        ):
            return email_change_request
        raise Http404

    def get(self, request, *args, **kwargs):
        return Response(EmailChangeSerializer(self.get_object()).data)

    def post(self, request, *args, **kwargs):
        if not request.user.has_usable_password():
            raise _password_not_set()
        email_change_request = self.validated_serializer().form.save()
        mailer_kwargs = {
            "base_url": self.base_url,
            "confirmation_url": self.frontend_url("email_change_confirm"),
            "cancel_url": self.frontend_url("email_change_cancel"),
        }
        flows.send_email_change_emails(
            request.user,
            email_change_request,
            email_change_request_mailer=partial(
                self.email_change_request_mailer, **mailer_kwargs
            ),
            proposed_email_exists_mailer=partial(
                self.proposed_email_exists_mailer, **mailer_kwargs
            ),
        )
        return Response(
            EmailChangeSerializer(email_change_request).data,
            status=HTTPStatus.CREATED,
        )

    def delete(self, request, *args, **kwargs):
        self.get_object().delete()
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses=EmailChangeSerializer))
class EmailChangeConfirmView(BaseView):
    """
    Confirm the email change request with the token from one of its emails.

    The email address changes once both the current and proposed address confirm it.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = EmailChangeConfirmSerializer
    email_changed_mailer = mailers.EmailChangedMailer

    def post(self, request, *args, **kwargs):
        email_change_request = flows.confirm_email_change(
            self.validated_serializer().form
        )
        if email_change_request is None:
            raise exceptions.ValidationError(
                {
                    api_settings.NON_FIELD_ERRORS_KEY: [
                        _(
                            "Sorry, changing your email address is not possible because"
                            " an account with this email address already exists."
                        )
                    ]
                }
            )
        if email_change_request.is_complete():
            self.email_changed_mailer(
                request.user,
                email_change_request=email_change_request,
                base_url=self.base_url,
            ).send()
        return Response(EmailChangeSerializer(email_change_request).data)
