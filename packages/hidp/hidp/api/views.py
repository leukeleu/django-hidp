import logging

from datetime import timedelta
from http import HTTPStatus

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import BooleanField

from django.contrib.auth import get_user_model
from django.http import Http404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts import auth as hidp_auth
from hidp.accounts import mailers, tokens
from hidp.accounts.email_change import Recipient
from hidp.accounts.mailers import (
    EmailVerificationMailer,
    PasswordChangedMailer,
    PasswordResetRequestMailer,
    SetPasswordMailer,
)
from hidp.accounts.models import EmailChangeRequest

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
    EmailChangeSerializer,
    EmailVerificationConfirmSerializer,
    EmailVerificationTokenSerializer,
    LoginSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetRequestSerializer,
    UserSerializer,
)
from .utils import (
    CSRFProtectedAPIView,
    get_authentication_classes,
    get_frontend_url,
)

UserModel = get_user_model()

logger = logging.getLogger(__name__)

AUTH_STATE_RESPONSES = {
    HTTPStatus.OK: AuthStateSerializer,
    HTTPStatus.UNAUTHORIZED: AuthStateSerializer,
}


def _base_url(request):
    return request.build_absolute_uri("/")


@extend_schema_view(
    retrieve=extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.STR,
                enum=["me"],
                location="path",
                description="Key identifying user, can only have value `me`.",
            ),
        ]
    ),
    update=extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.STR,
                enum=["me"],
                location="path",
                description="Key identifying user, can only have value `me`.",
            ),
        ]
    ),
)
class UserViewSet(
    mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet
):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserModel.objects.all()

    def get_authenticators(self):  # noqa: PLR6301 (no-self-use)
        return [
            authentication_class()
            for authentication_class in get_authentication_classes()
        ]

    def get_object(self):
        # Users can only ever access themselves using the "me" shortcut.
        if self.kwargs.get(self.lookup_url_kwarg or self.lookup_field) == "me":
            return self.request.user
        raise Http404


@method_decorator(ensure_csrf_cookie, name="dispatch")
@method_decorator(never_cache, name="dispatch")
@extend_schema_view(get=extend_schema(responses=AUTH_STATE_RESPONSES))
class SessionView(GenericAPIView):
    """
    Describe the authentication state of the current session.

    Also sets the CSRF cookie, which clients need for every unsafe request.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        return auth_state_response(request)


@method_decorator(sensitive_post_parameters("username", "password"), name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
@method_decorator(
    rate_limit(key=ip_username_rate_limit_key, rate="10/m", method="POST"),
    name="dispatch",
)
@extend_schema_view(post=extend_schema(responses=AUTH_STATE_RESPONSES))
class LoginView(CSRFProtectedAPIView, GenericAPIView):
    """
    Log in with a username and password.

    Responds with the authentication state. A user whose email address is not
    verified is not logged in, is sent a verification email, and the response has a
    pending `email_verify` step.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    serializer_class = LoginSerializer
    verification_mailer = EmailVerificationMailer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # User is authenticated and is allowed to log in.
        user = serializer.validated_data["user"]

        # Only log in the user if their email address has been verified.
        if user.email_verified:
            hidp_auth.login(request, user)
            return auth_state_response(request)

        # If the user's email address is not verified, send a verification email.
        self.verification_mailer(
            user,
            base_url=_base_url(request),
            verification_url=get_frontend_url(
                "email_verification", base_url=_base_url(request)
            ),
        ).send()
        start_email_verification(request, user)
        return auth_state_response(request)


@extend_schema_view(
    post=extend_schema(
        request=None,
        responses={HTTPStatus.UNAUTHORIZED: AuthStateSerializer},
    )
)
class LogoutView(CSRFProtectedAPIView, GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = []

    def post(self, request, *args, **kwargs):  # noqa: PLR6301
        """
        Logs out the user, regardless of whether a user is logged in.

        Enforces that a CSRF token is provided.
        """
        hidp_auth.logout(request)
        return auth_state_response(request)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        request=None,
        responses={HTTPStatus.NO_CONTENT: None},
    ),
)
class EmailVerificationResendView(CSRFProtectedAPIView, GenericAPIView):
    """
    Resend the verification email to the user this session is waiting for.

    Always responds with 204, so the response does not reveal whether an email
    was sent.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    verification_mailer = EmailVerificationMailer

    def post(self, request, *args, **kwargs):
        user = get_email_verification_user(request)
        if user is not None:
            self.verification_mailer(
                user,
                base_url=_base_url(request),
                verification_url=get_frontend_url(
                    "email_verification", base_url=_base_url(request)
                ),
            ).send()
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
class EmailVerificationVerifyView(CSRFProtectedAPIView, GenericAPIView):
    """
    Check an email verification token before confirming it.

    Tells the client whether the confirmation must include a first and last name.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    serializer_class = EmailVerificationTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        return Response(
            {"requires_name": not (user.first_name and user.last_name)},
            status=HTTPStatus.OK,
        )


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(responses={HTTPStatus.NO_CONTENT: None}),
)
class EmailVerificationConfirmView(CSRFProtectedAPIView, GenericAPIView):
    """Mark the email address as verified. The user still has to log in."""

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    serializer_class = EmailVerificationConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        update_fields = ["email_verified"]
        for field in ("first_name", "last_name"):
            if field in serializer.validated_data:
                setattr(user, field, serializer.validated_data[field])
                update_fields.append(field)
        user.email_verified = timezone.now()
        user.save(update_fields=update_fields)
        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
        },
    )
)
class PasswordResetRequestView(CSRFProtectedAPIView, GenericAPIView):
    """
    Email a password reset link, or a set password link to a user without a password.

    Always responds with 204, so the response does not reveal whether an account
    exists.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    serializer_class = PasswordResetRequestSerializer

    def send_email(self, user):
        base_url = _base_url(self.request)
        mailer_kwargs = {"user": user, "base_url": base_url}

        if user.has_usable_password():
            mailer_class = PasswordResetRequestMailer
            mailer_kwargs["password_reset_url"] = get_frontend_url(
                "password_reset", base_url=base_url
            )
        else:
            mailer_class = SetPasswordMailer
            mailer_kwargs["set_password_url"] = get_frontend_url(
                "set_password", base_url=base_url
            )

        try:
            mailer_class(**mailer_kwargs).send()
        except Exception:
            # Do not leak the existence of the user. Log the error and
            # continue as if the email was sent successfully.
            logger.exception("Failed to send password reset email.")

    def post(self, request, *args, **kwargs):
        # Get user from serializer if it exists for given email
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        # Send an password reset email if the user exists
        if user:
            self.send_email(user)

        return Response(status=HTTPStatus.NO_CONTENT)


@method_decorator(
    sensitive_post_parameters("token", "uidb64", "new_password"), name="dispatch"
)
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
        },
    )
)
class PasswordResetConfirmationView(CSRFProtectedAPIView, GenericAPIView):
    """
    Set a new password for the user identified by the password reset token.

    Changing the password invalidates the user's existing sessions. The user still
    has to log in.
    """

    authentication_classes = [SessionAuthentication]
    permission_classes = []
    serializer_class = PasswordResetConfirmationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        PasswordChangedMailer(
            user,
            base_url=_base_url(request),
            password_reset_url=get_frontend_url(
                "password_reset_request", base_url=_base_url(request)
            ),
        ).send()
        return Response(status=HTTPStatus.NO_CONTENT)


@extend_schema_view(
    create=extend_schema(
        responses={201: OpenApiResponse(None)},
    ),
)
class EmailChangeView(
    mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet
):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = EmailChangeSerializer

    def get_object(self):
        """
        Get the email change request to cancel.

        But only if there is a request for the current user that has not been confirmed
        by both the current and proposed email addresses, and has not expired.
        """
        change_request = (
            EmailChangeRequest.objects.filter(
                user=self.request.user,
                created_at__gte=(
                    timezone.now()
                    - timedelta(
                        seconds=tokens.email_change_token_generator.token_timeout
                    )
                ),
            )
            .exclude(
                confirmed_by_current_email=True,
                confirmed_by_proposed_email=True,
            )
            .first()
        )

        if not change_request:
            raise Http404

        return change_request

    def create(self, request, *args, **kwargs):
        super().create(request, *args, **kwargs)
        self.send_mail(self.created_instance)

        return Response(status=HTTPStatus.CREATED)

    def perform_create(self, serializer):
        """Create an email change request and save it on this view instance."""
        self.created_instance = serializer.save()

    def send_mail(self, email_change_request):
        """Send the email change confirmation emails."""
        mailer_kwargs = {
            "user": self.request.user,
            "email_change_request": email_change_request,
            "base_url": _base_url(self.request),
        }
        confirmation_url = get_frontend_url(
            "email_change_confirm", base_url=_base_url(self.request)
        )
        cancel_url = get_frontend_url(
            "email_change_cancel", base_url=_base_url(self.request)
        )
        mailers.EmailChangeRequestMailer(
            **mailer_kwargs,
            recipient=Recipient.CURRENT_EMAIL,
            confirmation_url=confirmation_url,
            cancel_url=cancel_url,
        ).send()

        existing_user = UserModel.objects.filter(
            email__iexact=email_change_request.proposed_email
        ).first()

        if existing_user and not existing_user.is_active:
            # Do nothing if the user exists but is not active.
            return

        if existing_user:
            # Send an email to the proposed email address to inform them that
            # an account with this email address already exists.
            mailers.ProposedEmailExistsMailer(
                **mailer_kwargs,
                recipient=Recipient.PROPOSED_EMAIL,
                cancel_url=cancel_url,
            ).send()
            return

        mailers.EmailChangeRequestMailer(
            **mailer_kwargs,
            recipient=Recipient.PROPOSED_EMAIL,
            confirmation_url=confirmation_url,
            cancel_url=cancel_url,
        ).send()


@extend_schema_view(
    put=extend_schema(
        responses={
            200: inline_serializer(
                name="UpdateChangeEmailRequestResponse",
                fields={
                    "confirmed_by_current_email": BooleanField(),
                    "confirmed_by_proposed_email": BooleanField(),
                },
            )
        },
    ),
)
class EmailChangeConfirmView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = EmailChangeConfirmSerializer

    def get_object(self):
        """
        Find the email change request associated with the token in the session.

        Exclude the request if it has already been confirmed for this email address.

        Raises a 404 exception if no request is found.
        """
        email_change_request = (
            EmailChangeRequest.objects.filter(id=self.token_uuid)
            .exclude(**{f"confirmed_by_{self.token_recipient}": True})
            .first()
        )

        if (
            email_change_request is None
            or email_change_request.user != self.request.user
        ):
            raise Http404

        return email_change_request

    def put(self, request, *args, **kwargs):
        """
        Get the existing email change request and update it.

        If the request is complete the email of the user is updated and
        an email to inform the user is sent.

        Returns a response containing whether the request is confirmed
        by the current and proposed mail. If both have confirmed the request
        the change can be considered complete.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # get the token_data from the validated serializer first so it can be used in
        # `get_object()` to get the instance. Then set the instance on the serializer.
        token_data = serializer.validated_data["confirmation_token"]
        self.token_recipient, self.token_uuid = (
            token_data["recipient"],
            token_data["uuid"],
        )
        email_change_request = self.get_object()
        serializer.instance = email_change_request

        instance = serializer.save()

        if instance.is_complete():
            self.send_email(instance)

        return Response(
            {
                "confirmed_by_current_email": instance.confirmed_by_current_email,
                "confirmed_by_proposed_email": instance.confirmed_by_proposed_email,
            },
            status=HTTPStatus.OK,
        )

    def send_email(self, email_change_request):
        """Send the email changed email."""
        mailers.EmailChangedMailer(
            self.request.user,
            email_change_request=email_change_request,
            base_url=self.request.build_absolute_uri("/"),
        ).send()
