from importlib import import_module

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
)
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore as DbSessionStore
from django.http import Http404

from .serializers import SessionSerializer, UserSerializer

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
SessionStoreModel = SessionStore().model

UserModel = get_user_model()


user_id_me_parameter = OpenApiParameter(
    name="id",
    type=OpenApiTypes.STR,
    enum=["me"],
    location="path",
    description="Key identifying user, can only have value `me`.",
)


@extend_schema_view(
    retrieve=extend_schema(parameters=[user_id_me_parameter]),
    update=extend_schema(parameters=[user_id_me_parameter]),
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


session_id_parameter = OpenApiParameter(
    name="id",
    type=OpenApiTypes.STR,
    location="path",
    description="Key identifying session.",
)


@extend_schema_view(destroy=extend_schema(parameters=[session_id_parameter]))
class SessionViewSet(
    mixins.ListModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet
):
    authentication_classes = [SessionAuthentication]
    queryset = SessionStoreModel.objects.all()
    serializer_class = SessionSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        session_key = self.kwargs[lookup_url_kwarg]
        session = SessionStore(session_key=session_key)

        if not session.exists(session_key=session_key):
            raise Http404

        # This returns a SessionStore object (a subclass of
        # django.contrib.sessions.backends.base.SessionBase)
        return session

    def list(self, request, *args, **kwargs):
        if not issubclass(SessionStore, DbSessionStore):
            raise NotImplementedError(
                "Listing sessions is only supported for "
                "database-based session backends."
            )

        return super().list(request, *args, **kwargs)
