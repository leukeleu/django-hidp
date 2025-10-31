from http import HTTPStatus

from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth import get_user_model
from django.http import Http404
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

from hidp.accounts.auth import login
from hidp.accounts.mailers import EmailVerificationMailer
from hidp.api.constants import LoginGrant

from .serializers import LoginSerializer, UserSerializer

UserModel = get_user_model()


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
class LoginView(GenericAPIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = LoginSerializer
    verification_mailer = EmailVerificationMailer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        grant = serializer.validated_data["grant"]

        if not user.email_verified:
            self.verification_mailer(
                user,
                base_url=request.build_absolute_uri("/"),
            ).send()
            return Response({}, status=HTTPStatus.UNAUTHORIZED)

        if grant == LoginGrant.SESSION:
            login(request, user)
            return Response({}, status=HTTPStatus.OK)
        elif grant == LoginGrant.BEARER:
            # TODO: Implement token login
            return Response({}, status=HTTPStatus.OK)
