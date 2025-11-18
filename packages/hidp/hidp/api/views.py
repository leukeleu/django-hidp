import logging

from http import HTTPStatus

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import BooleanField

from django.conf import settings
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.http import Http404
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts import auth as hidp_auth
from hidp.accounts.mailers import (
    EmailVerificationMailer,
    PasswordChangedMailer,
    PasswordResetRequestMailer,
    SetPasswordMailer,
)
from hidp.api.utils import CSRFProtectedAPIView

from .serializers import (
    LoginSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetRequestSerializer,
    UserSerializer,
)

UserModel = get_user_model()

logger = logging.getLogger(__name__)


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
    authentication_classes = [SessionAuthentication, OAuth2Authentication]
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserModel.objects.all()

    def get_object(self):
        # Users can only ever access themselves using the "me" shortcut.
        if self.kwargs.get(self.lookup_url_kwarg or self.lookup_field) == "me":
            return self.request.user
        raise Http404


@method_decorator(sensitive_post_parameters("username", "password"), name="dispatch")
@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
            HTTPStatus.UNAUTHORIZED: None,
        },
    )
)
class LoginView(GenericAPIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # User is authenticated and is allowed to log in.
        user = serializer.validated_data["user"]

        # Only log in the user if their email address has been verified.
        if user.email_verified:
            hidp_auth.login(request, user)
            return Response(status=HTTPStatus.NO_CONTENT)

        # If the user's email address is not verified, send a verification email.
        EmailVerificationMailer(
            user,
            base_url=request.build_absolute_uri("/"),
            verification_url=settings.EMAIL_VERIFICATION_URL,
        ).send()
        return Response(status=HTTPStatus.UNAUTHORIZED)


@extend_schema_view(
    post=extend_schema(
        request=None,
        responses={
            HTTPStatus.NO_CONTENT: None,
        },
    )
)
class LogoutView(CSRFProtectedAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = []

    def post(self, request, *args, **kwargs):  # noqa: PLR6301
        """
        Logs out the user, regardless of whether a user is logged in.

        Enforces that a CSRF token is provided.
        """
        hidp_auth.logout(request)
        return Response(status=HTTPStatus.NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        responses={
            HTTPStatus.OK: inline_serializer(
                name="GetEmailVerifiedResponse",
                fields={
                    "email_verified": BooleanField(),
                },
            )
        },
    )
)
class EmailVerifiedView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):  # noqa: PLR6301
        return Response(
            {"email_verified": bool(request.user.email_verified)}, status=HTTPStatus.OK
        )


@extend_schema_view(
    post=extend_schema(
        request=None,
        responses={HTTPStatus.NO_CONTENT: None},
    ),
)
class EmailVerificationResendView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):  # noqa: PLR6301
        if request.user.email_verified:
            raise ValidationError("Email is already verified.")
        EmailVerificationMailer(
            request.user,
            base_url=request.build_absolute_uri("/"),
            verification_url=settings.EMAIL_VERIFICATION_URL,
        ).send()
        return Response(status=HTTPStatus.NO_CONTENT)


@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
        },
    )
)
class PasswordResetRequestView(GenericAPIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = PasswordResetRequestSerializer

    def send_email(self, user):
        mailer_kwargs = {"user": user, "base_url": self.request.build_absolute_uri("/")}

        if user.has_usable_password():
            mailer_class = PasswordResetRequestMailer
            mailer_kwargs["password_reset_url"] = settings.PASSWORD_RESET_URL
        else:
            mailer_class = SetPasswordMailer
            mailer_kwargs["set_password_url"] = settings.SET_PASSWORD_URL

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


@extend_schema_view(
    post=extend_schema(
        responses={
            HTTPStatus.NO_CONTENT: None,
        },
    )
)
class PasswordResetConfirmationView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordResetConfirmationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_password = serializer.validated_data["new_password"]
        request.user.set_password(new_password)
        request.user.save()

        # Make sure the current sessions remains valid after the password change
        update_session_auth_hash(request, request.user)

        PasswordChangedMailer(
            request.user,
            base_url=request.build_absolute_uri("/"),
            password_reset_url=settings.PASSWORD_CHANGED_URL,
        ).send()
        return Response(status=HTTPStatus.NO_CONTENT)
