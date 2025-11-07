from http import HTTPStatus

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
)
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth import get_user_model
from django.http import Http404
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts import auth as hidp_auth
from hidp.accounts.mailers import EmailVerificationMailer

from .serializers import LoginSerializer, UserSerializer

UserModel = get_user_model()


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
    verification_mailer = EmailVerificationMailer

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
        self.verification_mailer(
            user,
            base_url=request.build_absolute_uri("/"),
        ).send()
        return Response(status=HTTPStatus.UNAUTHORIZED)


class EmailVerifiedView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):  # noqa: PLR6301
        return Response(
            {"email_verified": bool(request.user.email_verified)}, status=HTTPStatus.OK
        )


class EmailVerificationResendView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    verification_mailer = EmailVerificationMailer

    def post(self, request, *args, **kwargs):
        if request.user.email_verified:
            raise ValidationError("Email is already verified.")
        self.verification_mailer(
            request.user,
            base_url=request.build_absolute_uri("/"),
            verification_url=settings.EMAIL_VERIFICATION_URL,
        ).send()
        return Response(status=HTTPStatus.NO_CONTENT)
