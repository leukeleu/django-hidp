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
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import BooleanField

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import Http404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts import auth as hidp_auth
from hidp.accounts import mailers, tokens
from hidp.accounts.email_change import Recipient
from hidp.accounts.mailers import EmailVerificationMailer
from hidp.accounts.models import EmailChangeRequest
from hidp.api.utils import CSRFProtectedAPIView

from .serializers import (
    EmailChangeConfirmSerializer,
    EmailChangeSerializer,
    LoginSerializer,
    UserSerializer,
)

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
            "base_url": self.request.build_absolute_uri("/"),
        }
        mailers.EmailChangeRequestMailer(
            **mailer_kwargs,
            recipient=Recipient.CURRENT_EMAIL,
            confirmation_url=settings.EMAIL_CHANGE_CONFIRMATION_URL,
            cancel_url=settings.EMAIL_CHANGE_CANCEL_URL,
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
                cancel_url=settings.EMAIL_CHANGE_CANCEL_URL,
            ).send()
            return

        mailers.EmailChangeRequestMailer(
            **mailer_kwargs,
            recipient=Recipient.PROPOSED_EMAIL,
            confirmation_url=settings.EMAIL_CHANGE_CONFIRMATION_URL,
            cancel_url=settings.EMAIL_CHANGE_CANCEL_URL,
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
