from datetime import timedelta

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
)
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, status, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth import get_user_model
from django.http import Http404
from django.utils import timezone

from hidp.accounts import tokens
from hidp.accounts.models import EmailChangeRequest

from .serializers import (
    EmailChangeConfirmSerializer,
    EmailChangeSerializer,
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

    def perform_create(self, serializer):
        self.created_instance = serializer.save()

    def create(self, request, *args, **kwargs):
        super().create(request, *args, **kwargs)
        self.send_mail(self.created_instance)

        return Response(status=status.HTTP_201_CREATED)

    def send_mail(self, email_change_request):
        # TODO: for requesting email change implement equivalent of
        # hidp/accounts/views.py:EmailChangeRequestView.send_email()
        pass


class EmailChangeConfirmView(GenericAPIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = EmailChangeConfirmSerializer

    def post(self, request, *args, **kwargs):
        # TODO: for confirming email change implement equivalent of
        # hidp/accounts/views.py:EmailChangeConfirmView.form_valid()
        pass
