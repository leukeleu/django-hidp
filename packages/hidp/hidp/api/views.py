from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import mixins, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import get_user_model
from django.http import Http404

from .serializers import UserSerializer

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
