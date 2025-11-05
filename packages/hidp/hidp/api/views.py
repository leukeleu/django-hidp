import logging

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
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth import get_user_model, update_session_auth_hash
from django.http import Http404

from hidp.accounts.mailers import (
    PasswordResetRequestMailer,
    SetPasswordMailer,
)

from .serializers import (
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
    password_reset_request_mailer = PasswordResetRequestMailer
    set_password_mailer = SetPasswordMailer

    def post(self, request, *args, **kwargs):
        # Get user from serializer if it exists for given email
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        # Send an password reset email if the user exists
        if user:
            mailer_class = (
                self.password_reset_request_mailer
                if user.has_usable_password()
                else self.set_password_mailer
            )
            try:
                mailer_class(
                    user=user,
                    base_url=self.request.build_absolute_uri("/"),
                ).send()
            except Exception:
                # Do not leak the existence of the user. Log the error and
                # continue as if the email was sent successfully.
                logger.exception("Failed to send password reset email.")

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

        return Response(status=HTTPStatus.NO_CONTENT)
